"""Fixed metadata SQL for future dedicated cleanup wiring; declarations only."""
# Four bounded index ranges: pending retry cannot starve new expirations.
# The cutoff lower bound skips historical ready rows before rollout.
CANDIDATES = ' UNION ALL '.join(
    """(SELECT d.id,d.owner_id FROM mail_management.mail_client_downloads w FORCE INDEX(owner_lifecycle_expiry_v1)
JOIN mail_management.mail_client_devices d ON w.device_id=d.id AND w.owner_id=d.owner_id
WHERE w.state='""" + state + "' AND w.expires_at>=FROM_UNIXTIME(%s) AND w.expires_at<=FROM_UNIXTIME(%s)\n"
    "AND d.created_at>=FROM_UNIXTIME(%s) AND d.state='" + device + "'\n"
    "ORDER BY w.expires_at,w.device_id LIMIT 8)"
    for state, device in (('ready','active'),('consumed','active'),('unknown','active'),('expired','revoke_pending')))
CANDIDATE_PARAMS = 4
OWNER_LOCK = 'SELECT owner_id FROM mail_management.mail_client_owner_locks WHERE owner_id=%s FOR UPDATE'
LOCKED_ROW = """SELECT d.id,d.owner_id,d.owner_epoch,d.owner_identity_version,d.revocation_generation,d.state,
CAST(FLOOR(UNIX_TIMESTAMP(d.created_at)) AS UNSIGNED),w.state,CAST(FLOOR(UNIX_TIMESTAMP(w.expires_at)) AS UNSIGNED),w.owner_id
FROM mail_management.mail_client_devices d
JOIN mail_management.mail_client_downloads w ON w.device_id=d.id AND w.owner_id=d.owner_id
WHERE d.id=%s AND d.owner_id=%s FOR UPDATE"""
DENY = """UPDATE mail_management.mail_client_devices SET state='revoke_pending',revocation_generation=%s,pending_components=%s
WHERE id=%s AND owner_id=%s AND state='active' AND revocation_generation=%s"""
EXPIRE_DOWNLOAD = """UPDATE mail_management.mail_client_downloads SET state='expired'
WHERE device_id=%s AND owner_id=%s AND state IN ('ready','consumed','unknown')"""
FINISH = """UPDATE mail_management.mail_client_devices SET state=%s,pending_components=%s
WHERE id=%s AND owner_id=%s AND state='revoke_pending' AND revocation_generation=%s"""
# New issuer cleanup RPC must verify this exact committed state; it cannot use a
# fabricated browser session/Owner envelope or merely trust an expired-ID list.
ISSUER_CLAIM = """SELECT d.revocation_generation,d.state,w.state,w.expires_at<=UTC_TIMESTAMP(),d.owner_epoch,d.owner_identity_version
FROM mail_management.mail_client_devices d JOIN mail_management.mail_client_downloads w
ON w.device_id=d.id AND w.owner_id=d.owner_id WHERE d.id=%s AND d.owner_id=%s LIMIT 2"""
