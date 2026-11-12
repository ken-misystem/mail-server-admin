"""Candidate SQL only, no DB connection. Preserve old linked credentials unchanged."""

ELIGIBLE = (
    "c.enabled=1 AND ((c.user_id IS NULL AND c.sender_address IS NOT NULL) "
    "OR (c.user_id IS NOT NULL AND c.sender_address IS NULL AND u.active=1 AND d.active=1))"
)
JOINS = (
    "FROM mail_management.mail_legacy_smtp_credentials c "
    "LEFT JOIN mailserver.virtual_users u ON u.id=c.user_id "
    "LEFT JOIN mailserver.virtual_domains d ON d.id=u.domain_id "
)
AUTH_QUERY = (
    "SELECT c.password_hash AS password, CONCAT('legacy-smtp-',CAST(c.id AS CHAR)) AS user "
    + JOINS + "WHERE BINARY c.login_id=BINARY '%{user}' AND '%{protocol}'='legacy-smtp' AND "
    + ELIGIBLE + " LIMIT 1"
)
# Exact key only. No wildcard, catch-all, alias or domain-wide fallback.
# LOWER() applies to the lookup value, not the indexed sender column.
SENDER_QUERY = (
    "SELECT CONCAT('legacy-smtp-',CAST(c.id AS CHAR)) " + JOINS
    + "WHERE ((c.user_id IS NULL AND c.sender_address=LOWER('%s')) "
    "OR (c.user_id IS NOT NULL AND u.email='%s')) AND " + ELIGIBLE
)
