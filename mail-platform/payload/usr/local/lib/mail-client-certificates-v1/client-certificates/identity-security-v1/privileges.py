"""INERT explicit column grants; no user creation, passwords, DB execution.

All names below are proposed capabilities, not claims about existing principals.
Only a later reviewed manifest may assign distinct localhost accounts to them.
"""
import re
from identity import require

DEVICE_READ = ("id", "owner_id", "owner_epoch", "owner_identity_version", "label", "request_id",
               "request_digest", "created_at", "state", "certificate_sha256", "issuer_id", "serial",
               "not_before", "expires_at", "revocation_generation", "pending_components", "sequence_id")
DEVICE_INSERT = DEVICE_READ[:9] + ("pending_components",)
DEVICE_UPDATE = ("state", "certificate_sha256", "issuer_id", "serial", "not_before", "expires_at",
                 "revocation_generation", "pending_components")
DOWNLOAD = ("device_id", "owner_id", "session_binding_hash", "handle_hash", "expires_at", "state")
CURRENT = ("owner_id", "auth_epoch", "identity_version", "canonical_mailbox", "active")
LOGIN = ("login_name", "owner_id", "active")
LOCK = ("owner_id", "identity_version", "canonical_mailbox", "domain_id", "owner_created_at",
        "domain_created_at", "retired")
JOURNAL = ("device_id", "issuer_id", "serial", "state", "certificate_sha256", "not_before", "expires_at")
MG = "mail_management."
AUTH = {
    "mailserver.virtual_users": ("id", "domain_id", "email", "active", "auth_epoch", "created_at"),
    "mailserver.virtual_domains": ("id", "name", "active", "created_at"),
    "mailserver.virtual_domain_aliases": ("alias_domain", "target_domain_id", "active"),
    "mailserver.virtual_aliases": ("source", "active"),
}
READ_VIEWS = (("SELECT", MG+"mail_client_current_owners", CURRENT),
              ("SELECT", MG+"mail_client_login_owners", LOGIN))
POLICY = {
    "view_definer": tuple(("SELECT", table, cols) for table, cols in AUTH.items()) + (
        ("SELECT", MG+"mail_client_owner_locks", LOCK),) + READ_VIEWS[:1],
    "identity_reader": READ_VIEWS + (("SELECT", "roundcube.users", ("user_id", "username", "mail_host")),),
    "orchestrator": READ_VIEWS[:1] + (
        ("SELECT", MG+"mail_client_owner_locks", ("owner_id",)),
        ("SELECT", MG+"mail_client_devices", DEVICE_READ),
        ("INSERT", MG+"mail_client_devices", DEVICE_INSERT),
        ("UPDATE", MG+"mail_client_devices", DEVICE_UPDATE),
        ("SELECT", MG+"mail_client_downloads", DOWNLOAD),
        ("INSERT", MG+"mail_client_downloads", DOWNLOAD),
        ("UPDATE", MG+"mail_client_downloads", ("state",))),
    "issuer_journal": READ_VIEWS[:1] + (
        ("SELECT", MG+"mail_client_owner_locks", ("owner_id",)),
        ("SELECT", MG+"mail_client_devices", DEVICE_READ[:-1]),
        ("SELECT", MG+"mail_client_issuer_journal", JOURNAL),
        ("INSERT", MG+"mail_client_issuer_journal", JOURNAL[:4]),
        ("UPDATE", MG+"mail_client_issuer_journal", ("state", "certificate_sha256", "not_before", "expires_at"))),
    "gateway_reader": READ_VIEWS + (
        ("SELECT", MG+"mail_client_devices", ("id", "certificate_sha256", "owner_id", "owner_epoch",
             "owner_identity_version", "revocation_generation", "state", "not_before", "expires_at")),),
    "lifecycle_provisioner": tuple(("SELECT", table, cols) for table, cols in AUTH.items()) + (
        ("SELECT", MG+"mail_client_owner_locks", LOCK),
        ("INSERT", MG+"mail_client_owner_locks", tuple(c for c in LOCK if c != "identity_version")),
        ("UPDATE", MG+"mail_client_owner_locks", ("retired",))),
}


def render(manifest):
    require(type(manifest) is dict and set(manifest) == set(POLICY)
            and all(type(v) is str and re.fullmatch(r"[a-z][a-z0-9_]{2,31}", v)
                    and v not in {"root", "mailpop", "www_data", "adminuser"} for v in manifest.values())
            and len(set(manifest.values())) == len(POLICY), "distinct_new_principals", "grant_plan")
    lines = []
    for role, rules in POLICY.items():
        for verb, table, columns in rules:
            lines.append("GRANT " + verb + " (" + ",".join(columns) + ") ON " + table
                         + " TO '" + manifest[role] + "'@'localhost';")
    return "\n".join(lines) + "\n"


def validate_observed_grants(role, rows):
    """Feed sanitized privilege triples incl. global/schema/role inheritance.

    Caller must prove coverage of effective privileges, not only direct grants.
    Missing coverage must fail before this function; no grant repair/revoke here.
    """
    require(role in POLICY, "role_shape", "grant_check")
    expected = {(v, t, c) for v, t, cols in POLICY[role] for c in cols}
    require(type(rows) in (list, tuple) and all(type(row) is tuple and len(row) == 3 for row in rows),
            "grant_metadata_shape", "grant_check")
    require(set(rows) == expected, "effective_grant_difference", "grant_check")
    return True
