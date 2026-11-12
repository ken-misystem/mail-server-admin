<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Server-side inventory selection with bounded, literal search parameters. */
final readonly class AdminInventoryFilter
{
    public const TITLES = ['users'=>'利用者・利用上限', 'domains'=>'ドメイン管理',
        'aliases'=>'受信エイリアス管理', 'admins'=>'管理者一覧'];

    private function __construct(
        public string $section,
        public QuotaListFilter $search,
        public string $state,
        public string $domainChoice,
        public string $destinationChoice,
    ) {}

    public static function fromArray(array $input): self
    {
        $allowed = ['section','domain','q','page','per_page','state','domain_choice','destination_choice'];
        if (array_diff(array_keys($input), $allowed)) { throw new \DomainException('invalid_input'); }
        foreach ($input as $value) {
            if (!is_string($value) || strlen($value) > 254 || !preg_match('//u', $value)
                || preg_match('/[\x00-\x1f\x7f]/', $value)) { throw new \DomainException('invalid_input'); }
        }
        $section = $input['section'] ?? 'users';
        $state = $input['state'] ?? '';
        if (!isset(self::TITLES[$section]) || !in_array($state, ['', '0', '1'], true)) {
            throw new \DomainException('invalid_input');
        }
        $search = QuotaListFilter::fromArray(array_intersect_key($input, array_flip(['domain','q','page','per_page'])));
        if ($section === 'admins' && $search->domain !== '') { throw new \DomainException('invalid_input'); }
        $domain = trim($input['domain_choice'] ?? '');
        $destination = trim($input['destination_choice'] ?? '');
        if ($domain !== '') { $domain = AdminMailPolicy::domain($domain); }
        if ($destination !== '') { $destination = AdminMailPolicy::address($destination); }
        return new self($section, $search, $state, $domain, $destination);
    }

    public function predicates(): array
    {
        $column = match ($this->section) {
            'users', 'admins' => 'u.email', 'domains' => 'u.name', 'aliases' => 'u.source',
        };
        $where = [];
        $args = [];
        if ($this->search->q !== '') {
            $where[] = $column . " LIKE ? ESCAPE '!'";
            $args[] = str_replace(['!','%','_'], ['!!','!%','!_'], $this->search->q) . '%';
        }
        if ($this->search->domain !== '') {
            $where[] = ($this->section === 'domains' ? 'u.name' : 'd.name') . '=?';
            $args[] = $this->search->domain;
        }
        if ($this->state !== '') { $where[] = 'u.active=?'; $args[] = $this->state; }
        return [$where ? ' WHERE ' . implode(' AND ', $where) : '', $args];
    }

    public function values(?int $page = null): array
    {
        return ['section'=>$this->section, 'domain'=>$this->search->domain, 'q'=>$this->search->q,
            'page'=>(string)($page ?? $this->search->page), 'per_page'=>(string)$this->search->perPage,
            'state'=>$this->state, 'domain_choice'=>$this->domainChoice, 'destination_choice'=>$this->destinationChoice];
    }

    public function url(?int $page = null): string
    {
        return '/mail-admin/manage?' . http_build_query($this->values($page), '', '&', PHP_QUERY_RFC3986);
    }

    public static function returnTo(mixed $value): string
    {
        if ($value === null) { return '/mail-admin/manage'; }
        $prefix = '/mail-admin/manage?';
        if (!is_string($value) || strlen($value) > 4096 || !str_starts_with($value, $prefix)) {
            throw new \DomainException('invalid_return_path');
        }
        parse_str(substr($value, strlen($prefix)), $query);
        $filter = self::fromArray($query);
        if ($filter->url() !== $value) { throw new \DomainException('invalid_return_path'); }
        return $value;
    }
}
