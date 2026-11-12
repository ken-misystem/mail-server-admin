"""One additive column privilege; unknown outcome is never automatically retried."""
GRANT="GRANT SELECT (auth_epoch) ON mail_management.mail_admin_users TO 'mail_feature_reader'@'localhost'"
QUERIES=(
 ("reader","SELECT COUNT(*) FROM mysql.user WHERE User='mail_feature_reader' AND Host='localhost'",()),
 ("roles","SELECT COUNT(*) FROM mysql.roles_mapping WHERE User='mail_feature_reader' AND Host='localhost'",()),
 ("columns","SELECT COLUMN_NAME FROM information_schema.COLUMN_PRIVILEGES WHERE GRANTEE=%s AND TABLE_SCHEMA='mail_management' AND TABLE_NAME='mail_admin_users' AND PRIVILEGE_TYPE='SELECT' ORDER BY COLUMN_NAME",("'mail_feature_reader'@'localhost'",)),
 ("table","SELECT COUNT(*) FROM information_schema.TABLE_PRIVILEGES WHERE GRANTEE=%s AND TABLE_SCHEMA='mail_management' AND TABLE_NAME='mail_admin_users' AND PRIVILEGE_TYPE='SELECT'",("'mail_feature_reader'@'localhost'",)),
 ("schema","SELECT COUNT(*) FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE=%s AND TABLE_SCHEMA='mail_management' AND PRIVILEGE_TYPE='SELECT'",("'mail_feature_reader'@'localhost'",)),
 ("global","SELECT COUNT(*) FROM information_schema.USER_PRIVILEGES WHERE GRANTEE=%s AND PRIVILEGE_TYPE<>'USAGE'",("'mail_feature_reader'@'localhost'",)))
class GrantOutcomeUnknown(RuntimeError):pass
def metadata(cursor):
 facts={}
 for name,sql,args in QUERIES:
  cursor.execute(sql,args);facts[name]=cursor.fetchall()
 return facts
def require_minimal(facts,allowed):
 if not(facts["reader"]in([(1,)],((1,),))and all(facts[name]in([(0,)],((0,),))for name in("roles","table","schema","global"))and{r[0]for r in facts["columns"]}==set(allowed)):
  raise ValueError("reader_privilege_scope_changed")
def ensure(cursor,save):
 """Caller already holds deployment lock and has approved this exact GRANT."""
 before=metadata(cursor);have={r[0]for r in before["columns"]};base={"id","active","is_system_admin"}
 if have==base|{"auth_epoch"}:
  require_minimal(before,have);return{"created":False,"reused":True,"retained_on_restore":True}
 require_minimal(before,base)
 save("reader-grant-intent.json",{"column":"auth_epoch","principal":"mail_feature_reader@localhost","state":"intent","retained_on_restore":True})
 try:cursor.execute(GRANT)
 except BaseException:raise GrantOutcomeUnknown("column_GRANT_outcome_unknown_do_not_repeat")from None
 try:
  after=metadata(cursor);require_minimal(after,base|{"auth_epoch"})
  result={"created":True,"reused":False,"retained_on_restore":True}
  save("reader-grant-result.json",result)
  return result
 except BaseException:raise GrantOutcomeUnknown("column_GRANT_postcheck_or_record_unknown_do_not_repeat")from None
