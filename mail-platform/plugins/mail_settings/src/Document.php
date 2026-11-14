<?php
declare(strict_types=1);
namespace MiSystem\MailSettings;

/** Original RFC 5228 lexical document editor. SPDX-License-Identifier: MIT.
 * Comments and original token spellings survive a parse/render round trip.
 * The server's PUTSCRIPT remains the authority for extension semantics.
 */
final class Document
{
    public const MARKER = '# MI-SYSTEM sieve document v2';
    private array $tokens = [];
    private int $position = 0;
    private int $nodes = 0;

    private static function invalid(): never
    {
        throw new \DomainException('invalid_script');
    }

    private static function lex(string $source): array
    {
        if (strlen($source) > Script::MAX_BYTES || preg_match('//u', $source) !== 1 || str_contains($source, "\0")) self::invalid();
        $tokens = [];
        $offset = 0;
        $length = strlen($source);
        while ($offset < $length) {
            preg_match('/\G(?:[ \t\r\n]+|\#[^\r\n]*(?:\r\n|\n|\r|$)|\/\*[\s\S]*?\*\/)*/', $source, $match, 0, $offset);
            $prefix = $match[0];
            $offset += strlen($prefix);
            if ($offset === $length) break;
            $rest = substr($source, $offset);
            if (preg_match('/\Atext:[ \t]*(?:\#[^\r\n]*)?\r?\n/i', $rest, $match)) {
                $start = strlen($match[0]);
                if (!preg_match('/^\.\r?\n/m', $rest, $end, PREG_OFFSET_CAPTURE, $start)) self::invalid();
                $raw = substr($rest, 0, $end[0][1] + strlen($end[0][0]));
                $value = substr($rest, $start, $end[0][1] - $start);
                $value = preg_replace('/^\.\./m', '.', $value);
                $type = 'string';
            } elseif (preg_match('/\A"(?:[^"\\\\]|\\\\[\s\S])*"/', $rest, $match)) {
                $raw = $match[0];
                $value = preg_replace('/\\\\([\s\S])/', '$1', substr($raw, 1, -1));
                $type = 'string';
            } elseif (preg_match('/\A:[A-Za-z_][A-Za-z_0-9]*/', $rest, $match)) {
                $raw = $value = $match[0];
                $type = 'tag';
            } elseif (preg_match('/\A[0-9]+[KMG]?/i', $rest, $match)) {
                $raw = $value = $match[0];
                $type = 'number';
            } elseif (preg_match('/\A[A-Za-z_][A-Za-z_0-9]*/', $rest, $match)) {
                $raw = $value = $match[0];
                $type = 'word';
            } elseif (str_contains('[](){},;', $rest[0])) {
                $raw = $value = $rest[0];
                $type = 'punctuation';
            } else {
                self::invalid();
            }
            $tokens[] = ['type' => $type, 'value' => $value, 'raw' => $raw, 'prefix' => $prefix];
            if (count($tokens) > 8192) self::invalid();
            $offset += strlen($raw);
            $prefix = '';
        }
        return [$tokens, $prefix ?? ''];
    }

    public static function parse(string $source): array
    {
        $parser = new self();
        [$parser->tokens, $tail] = self::lex($source);
        $commands = $parser->commands(0, false);
        return ['format' => 2, 'commands' => $commands, 'tail' => $tail];
    }

    private function take(): array
    {
        if (!isset($this->tokens[$this->position]) || ++$this->nodes > 8192) self::invalid();
        return $this->tokens[$this->position++];
    }

    private function commands(int $depth, bool $block): array
    {
        if ($depth > 32) self::invalid();
        $commands = [];
        while (isset($this->tokens[$this->position])) {
            if ($this->at('}') && $block) return $commands;
            $head = $this->take();
            if ($head['type'] !== 'word') self::invalid();
            $arguments = [];
            while (isset($this->tokens[$this->position]) && !$this->at(';') && !$this->at('{')) {
                $arguments[] = $this->argument($depth + 1);
            }
            $end = $this->take();
            $body = null;
            $close = null;
            if ($end['value'] === '{') {
                $body = $this->commands($depth + 1, true);
                $close = $this->take();
                if ($close['value'] !== '}') self::invalid();
            }
            $commands[] = ['head' => $head, 'arguments' => $arguments, 'end' => $end, 'body' => $body, 'close' => $close];
        }
        if ($block) self::invalid();
        return $commands;
    }

    private function at(string $value): bool
    {
        return ($this->tokens[$this->position]['type'] ?? '') === 'punctuation'
            && $this->tokens[$this->position]['value'] === $value;
    }

    private function argument(int $depth): array
    {
        if ($depth > 32) self::invalid();
        $token = $this->take();
        if ($token['type'] !== 'punctuation' || $token['value'] === ',') return ['token' => $token];
        if (!in_array($token['value'], ['[', '('], true)) self::invalid();
        $expected = $token['value'] === '[' ? ']' : ')';
        $items = [];
        while (isset($this->tokens[$this->position]) && !$this->at($expected)) {
            $items[] = $this->argument($depth + 1);
        }
        $close = $this->take();
        if ($close['value'] !== $expected) self::invalid();
        return ['open' => $token, 'items' => $items, 'close' => $close];
    }

    private static function trivia(mixed $value): string
    {
        if (!is_string($value)) self::invalid();
        [$tokens, $tail] = self::lex($value);
        if ($tokens || $tail !== $value) self::invalid();
        return $value;
    }

    private static function token(array $token, ?string $punctuation = null): string
    {
        $type = $token['type'] ?? null;
        $value = $token['value'] ?? null;
        if (!is_string($value) || !is_string($type) || !is_string($token['raw'] ?? null)) self::invalid();
        $prefix = self::trivia($token['prefix'] ?? null);
        $raw = $token['raw'];
        try {
            [$original, $tail] = self::lex($raw);
            if (count($original) !== 1 || $tail !== '' || $original[0]['prefix'] !== ''
                || $original[0]['type'] !== $type || $original[0]['value'] !== $value) $raw = '';
        } catch (\DomainException) {
            $raw = '';
        }
        if ($type === 'string') {
            if (preg_match('//u', $value) !== 1 || str_contains($value, "\0")) self::invalid();
            if ($raw === '' && (str_contains($value, "\n") || str_contains($value, "\r"))) {
                $body = str_replace(["\r\n", "\r"], "\n", $value);
                if (!str_ends_with($body, "\n")) $body .= "\n";
                $body = preg_replace('/^\./m', '..', $body);
                $raw = "text:\r\n" . str_replace("\n", "\r\n", $body) . ".\r\n";
            } elseif ($raw === '') {
                $raw = '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $value) . '"';
            }
        } else {
            $patterns = ['word' => '/\A[A-Za-z_][A-Za-z_0-9]*\z/D', 'tag' => '/\A:[A-Za-z_][A-Za-z_0-9]*\z/D',
                'number' => '/\A[0-9]+[KMG]?\z/iD', 'punctuation' => '/\A[\[\](){},;]\z/D'];
            if (!isset($patterns[$type]) || !preg_match($patterns[$type], $value)) self::invalid();
            $raw = $value;
        }
        if ($punctuation !== null && ($type !== 'punctuation' || $value !== $punctuation)) self::invalid();
        return $prefix . $raw;
    }

    private static function arguments(array $arguments, int $depth, int &$budget): string
    {
        if ($depth > 32 || !array_is_list($arguments)) self::invalid();
        $source = '';
        foreach ($arguments as $argument) {
            if (--$budget < 0 || !is_array($argument)) self::invalid();
            if (isset($argument['token'])) {
                $token = $argument['token'];
                if (($token['type'] ?? '') === 'punctuation' && ($token['value'] ?? '') !== ',') self::invalid();
                $source .= self::token($token);
            } else {
                $open = $argument['open']['value'] ?? '';
                if (!in_array($open, ['[', '('], true)) self::invalid();
                $source .= self::token($argument['open'], $open)
                    . self::arguments($argument['items'], $depth + 1, $budget)
                    . self::token($argument['close'], $open === '[' ? ']' : ')');
            }
        }
        return $source;
    }

    private static function commandsSource(array $commands, int $depth, int &$budget): string
    {
        if ($depth > 32 || !array_is_list($commands)) self::invalid();
        $source = '';
        foreach ($commands as $command) {
            if (--$budget < 0 || !is_array($command) || ($command['head']['type'] ?? '') !== 'word') self::invalid();
            $source .= self::token($command['head']) . self::arguments($command['arguments'], $depth + 1, $budget);
            if ($command['body'] === null) {
                $source .= self::token($command['end'], ';');
            } else {
                $source .= self::token($command['end'], '{')
                    . self::commandsSource($command['body'], $depth + 1, $budget) . self::token($command['close'], '}');
            }
        }
        return $source;
    }

    public static function render(array $document): string
    {
        if (($document['format'] ?? null) !== 2) self::invalid();
        $budget = 8192;
        $source = self::commandsSource($document['commands'], 0, $budget) . self::trivia($document['tail']);
        self::parse($source);
        return $source;
    }
}
