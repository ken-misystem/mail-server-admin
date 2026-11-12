"""Add only two pinned protection tables to the existing broker database."""
import hashlib,re
class SchemaCommitUnknown(RuntimeError):pass
def need(value,label):
    if not value:raise ValueError(label)
SCHEMA_SHA256="e2541eb2905a12c19b5aac3cd7a2aeddbcbf49294307372d7a5beafe8dad36f7"
NAMES=("protection_settings","protection_requests")
def normalize(sql):return " ".join(sql.rstrip().rstrip(";").split())
def ensure(connection,raw):
    """Caller holds the deployment lock and has stopped the existing broker."""
    need(type(raw)is bytes and hashlib.sha256(raw).hexdigest()==SCHEMA_SHA256,"schema_source_pin")
    need(not connection.in_transaction,"schema_transaction_active")
    need(connection.execute("PRAGMA synchronous").fetchone()==(2,),"schema_FULL_required")
    text="\n".join(x for x in raw.decode("utf-8").splitlines()if not x.lstrip().startswith("--"))
    statements=[x.strip()for x in text.split(";")if x.strip()]
    need(len(statements)==2,"schema_inventory")
    for sql,name in zip(statements,NAMES):
        need(re.match(r"CREATE TABLE "+name+r"\s*\(",sql)is not None,"schema_table_boundary")
    created=[];existing=[];committing=False
    connection.execute("BEGIN IMMEDIATE")
    try:
        for sql,name in zip(statements,NAMES):
            rows=connection.execute("SELECT type,sql FROM sqlite_master WHERE name=?",(name,)).fetchall()
            need(len(rows)<=1,"schema_name_ambiguous")
            if rows:
                need(rows[0][0]=="table"and normalize(rows[0][1])==normalize(sql),"unknown_existing_protection_schema")
                existing.append(name)
            else:connection.execute(sql);created.append(name)
        if not created:
            connection.rollback()
            return {"created":[],"reused":existing,"commit_known":True,"rows_reset":False}
        committing=True
        connection.commit()
        return {"created":created,"reused":existing,"commit_known":True,"rows_reset":False}
    except Exception:
        if committing:raise SchemaCommitUnknown("protection_schema_commit_unknown")from None
        try:connection.rollback()
        except Exception:raise SchemaCommitUnknown("protection_schema_rollback_unknown")from None
        raise
