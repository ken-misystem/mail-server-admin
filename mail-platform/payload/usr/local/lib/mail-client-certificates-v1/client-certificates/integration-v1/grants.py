"""Integrated pure privilege planner; no GRANT execution or credential lookup."""
from dataclasses import dataclass
from compat import old_privileges as old, require

VIEW = old.MG + 'mail_client_login_owners'
ROLES = ('identity_reader', 'gateway_reader')
COLUMN_POLICY = {role: tuple(rule for rule in rules if not (role in ROLES and rule[1] == VIEW))
                 for role, rules in old.POLICY.items()}
TABLE_POLICY = {role: (('SELECT', VIEW),) if role in ROLES else () for role in old.POLICY}


@dataclass(frozen=True)
class ViewScope:
    columns: tuple
    security_type: str
    definer: str


def inspect_view(cursor, manifest):
    """Provisioning-time metadata cursor only; ordinary runtime roles need no SHOW VIEW.

    Caller owns the read-only transaction and must establish complete metadata
    visibility. No configuration, account rows, SHOW GRANTS or secrets are read.
    """
    old.render(manifest)  # Reuse the validated, distinct-new-principal name checks.
    cursor.execute("SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s "
                   "AND TABLE_NAME=%s ORDER BY ORDINAL_POSITION",
                   ('mail_management', 'mail_client_login_owners'))
    columns = cursor.fetchmany(5)
    require(type(columns) in (tuple, list) and all(type(r) in (tuple, list) and len(r) == 1 for r in columns),
            'view_metadata_shape', 'view_scope')
    cursor.execute("SELECT SECURITY_TYPE,DEFINER FROM information_schema.VIEWS WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s",
                   ('mail_management', 'mail_client_login_owners'))
    views = cursor.fetchmany(2)
    require(type(views) in (tuple, list) and len(views) == 1 and len(views[0]) == 2,
            'view_metadata_missing_or_ambiguous', 'view_scope')
    scope = ViewScope(tuple(r[0] for r in columns), views[0][0], views[0][1])
    validate_scope(scope, manifest)
    return scope


def validate_scope(scope, manifest):
    require(type(scope) is ViewScope and scope.columns == old.LOGIN and scope.security_type == 'DEFINER'
            and scope.definer == manifest['view_definer'] + '@localhost',
            'fixed_view_scope_required', 'view_scope')


def render(manifest, scope):
    source = old.render(manifest)
    validate_scope(scope, manifest)
    for role in ROLES:
        prior = "GRANT SELECT (login_name,owner_id,active) ON " + VIEW + " TO '" + manifest[role] + "'@'localhost';"
        after = "GRANT SELECT ON " + VIEW + " TO '" + manifest[role] + "'@'localhost';"
        require(source.count(prior) == 1, 'view_grant_anchor', 'grant_plan')
        source = source.replace(prior, after)
    return source


def validate_snapshot(snapshot):
    """Complete deployment-audit snapshot, not a self-connection privilege claim.

    Native collection/visibility provenance must be bound separately by the
    deployment reader. This pure function never asserts that provenance exists.
    """
    require(type(snapshot) is dict and set(snapshot) == {'roles', 'public_privilege_counts'},
            'grant_snapshot_shape', 'grant_check')
    require(type(snapshot['public_privilege_counts']) is dict and snapshot['public_privilege_counts'] == dict.fromkeys(
        ('COLUMN_PRIVILEGES', 'TABLE_PRIVILEGES', 'SCHEMA_PRIVILEGES', 'USER_PRIVILEGES'), 0)
        and all(type(v) is int for v in snapshot['public_privilege_counts'].values()),
        'public_privilege_difference', 'grant_check')
    require(type(snapshot['roles']) is dict and set(snapshot['roles']) == set(COLUMN_POLICY),
            'grant_role_coverage', 'grant_check')
    for role, row in snapshot['roles'].items():
        require(type(row) is dict and set(row) == {'column_privileges', 'table_privileges', 'schema_privileges',
            'global_privileges', 'enabled_roles', 'applicable_roles', 'column_grant_options', 'table_grant_options'},
            'grant_metadata_shape', 'grant_check')
        expected = sorted([verb, table, col] for verb, table, cols in COLUMN_POLICY[role] for col in cols)
        require(row['column_privileges'] == expected
                and row['table_privileges'] == sorted([list(r) for r in TABLE_POLICY[role]])
                and row['schema_privileges'] == [] and row['global_privileges'] == []
                and row['enabled_roles'] == [[None]] and row['applicable_roles'] == []
                and type(row['column_grant_options']) is int and row['column_grant_options'] == 0
                and type(row['table_grant_options']) is int and row['table_grant_options'] == 0,
                'effective_grant_difference', 'grant_check')
    return True

