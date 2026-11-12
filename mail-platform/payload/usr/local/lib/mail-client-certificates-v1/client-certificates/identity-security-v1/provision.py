"""INERT lifecycle-only provisioning transaction for NEW certificate metadata.

No automatic Web provisioning, deletes, owner-ID replacement or epoch writes.
Caller is a separately approved lifecycle actor, not an end-user UI process.
"""
from identity import canonical, uint, require, AdapterError

OWNER_LOCK = ("SELECT u.id,u.domain_id,u.email,u.created_at,d.created_at,u.active,d.active "
              "FROM mailserver.virtual_users u JOIN mailserver.virtual_domains d ON d.id=u.domain_id "
              "WHERE u.id=%s FOR UPDATE")
EXISTING = ("SELECT owner_id,identity_version,canonical_mailbox,domain_id,owner_created_at,domain_created_at,retired "
            "FROM mail_management.mail_client_owner_locks WHERE owner_id=%s FOR UPDATE")
INSERT = ("INSERT INTO mail_management.mail_client_owner_locks "
          "(owner_id,canonical_mailbox,domain_id,owner_created_at,domain_created_at,retired) "
          "VALUES (%s,%s,%s,%s,%s,0)")


def prepare_binding(connection, owner_id):
    """DB-API candidate only. Keeps all old rows; immutable binding on mismatch.

    Must be called in an explicit provisioning approval, NEVER by this folder's
    local launcher. The server has no certificate metadata tables installed yet.
    """
    uint(owner_id, positive=True)
    phase="provision_begin"
    try:
        connection.autocommit(False)
        cursor=connection.cursor()
        cursor.execute("SET SESSION time_zone = '+00:00'")
        cursor.execute("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.begin()
        cursor.execute(OWNER_LOCK,(owner_id,));source=cursor.fetchmany(2)
        require(len(source)==1 and len(source[0])==7,"source_missing_or_ambiguous",phase)
        uid,domain,email,created,domain_created,active,domain_active=source[0]
        require(type(uid) is int and uid==owner_id and type(domain) is int and 0<domain<2**32
                and type(active) in (int,bool) and active==1
                and type(domain_active) in (int,bool) and domain_active==1,
                "source_inactive_or_invalid",phase)
        email=canonical(email)
        cursor.execute(EXISTING,(owner_id,));old=cursor.fetchmany(2)
        require(len(old)<=1,"binding_ambiguous",phase)
        if old:
            row=old[0]
            require(len(row)==7 and type(row[1]) is int and row[1]>0
                    and row[0]==owner_id and tuple(row[2:6])==(email,domain,created,domain_created)
                    and type(row[6]) in (bool,int) and row[6]==0,
                    "immutable_binding_conflict",phase)
            version=row[1]
        else:
            phase="provision_insert"
            cursor.execute(INSERT,(owner_id,email,domain,created,domain_created))
            require(cursor.rowcount==1 and type(cursor.lastrowid) is int and cursor.lastrowid>0,
                    "binding_insert_unverified",phase)
            version=cursor.lastrowid
        phase="provision_commit"
        connection.commit()  # PyMySQL returns None on success.
        return version
    except AdapterError:
        connection.rollback();raise
    except Exception as error:
        try: connection.rollback()
        except Exception: pass
        code=error.args[0] if error.args and type(error.args[0]) is int else None
        raise AdapterError("provision_commit_unknown" if phase=="provision_commit" else "provision_failed",
                           phase=phase,native_code=code) from None
    finally:
        connection.close()
