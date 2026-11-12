<?php
declare(strict_types=1);
namespace MailServer\Management;

/** Display-only, bounded filters. No caller-supplied SQL or sort expressions. */
final class QuotaListFilter
{
    private function __construct(public readonly string $domain, public readonly string $q,
        public readonly int $page, public readonly int $perPage) {}

    public static function fromArray(array $input): self
    {
        if (array_diff(array_keys($input), ['domain','q','page','per_page'])) { throw new \DomainException('invalid_input'); }
        foreach ($input as $value) {
            if (!is_string($value) || strlen($value) > 253 || preg_match('/[\x00-\x1f\x7f]/', $value)
                || !preg_match('//u', $value)) { throw new \DomainException('invalid_input'); }
        }
        $domain = trim($input['domain'] ?? '');
        if ($domain !== '') { $domain = AdminMailPolicy::domain($domain); }
        $q = trim($input['q'] ?? '');
        if (strlen($q) > 128) { throw new \DomainException('invalid_input'); }
        $page = $input['page'] ?? '1'; $size = $input['per_page'] ?? '25';
        if (!preg_match('/^[1-9][0-9]{0,4}$/D', $page) || (int)$page > 80000
            || !in_array($size, ['25','50','100'], true)) { throw new \DomainException('invalid_input'); }
        return new self($domain, $q, (int)$page, (int)$size);
    }

    public function predicates(): array
    {
        $where = []; $args = [];
        if ($this->domain !== '') { $where[] = 'd.name=?'; $args[] = $this->domain; }
        if ($this->q !== '') {
            $where[] = "u.email LIKE ? ESCAPE '!'";
            $args[] = str_replace(['!','%','_'], ['!!','!%','!_'], $this->q).'%';
        }
        return [$where ? ' WHERE '.implode(' AND ', $where) : '', $args];
    }

    public function window(int $total): array
    {
        if ($total < 0 || $total > 2000000) { throw new \DomainException('browse_capacity'); }
        $pages = max(1, (int)ceil($total / $this->perPage));
        $page = min($this->page, $pages);
        return ['total'=>$total, 'page'=>$page, 'pages'=>$pages, 'per_page'=>$this->perPage,
            'offset'=>($page-1)*$this->perPage];
    }

    public function url(?int $page = null): string
    {
        return '/mail-admin/mailbox-quota?'.http_build_query(['domain'=>$this->domain,'q'=>$this->q,
            'per_page'=>$this->perPage,'page'=>$page ?? $this->page], '', '&', PHP_QUERY_RFC3986);
    }
}
