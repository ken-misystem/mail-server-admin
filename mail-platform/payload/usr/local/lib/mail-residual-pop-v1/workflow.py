"""One attempt per target; successful old data is never imported again."""
import continuation_policy as policy
def execute_target(uid,adapter,original3):
 try:
  adapter.begin()
  before=adapter.source_snapshot("before")
  existing=adapter.inventory()
  decision=policy.plan(uid,before,existing,original3)
  adapter.record("plan",decision)
  imported_summary=None
  if decision["import_required"]:
   raw=adapter.import_once(before)
   imported_summary=policy.summary(raw)
  pop_uidls=adapter.local_UIDLs(reuse_importer=decision["import_required"])
  after=adapter.source_snapshot("after")
  final_locations=adapter.inventory()
  policy.retained(before,after)
  verified=policy.destination(before["uidls"],final_locations,pop_uidls)
  policy.need(verified["complete"],"final_snapshot_verification_failed")
  latest=policy.destination(after["uidls"],final_locations,pop_uidls)
  # Newly arriving mail is reported; it never triggers an unapproved second import.
  result={"user_id":uid,"status":"pass","snapshot_verified":True,"decision":decision,"importer":imported_summary,"verified":verified,"source_before_count":before["count"],"source_after_count":after["count"],"new_on_old":len(set(after["uidls"])-set(before["uidls"])),"latest_observed_UIDLs_complete":latest["complete"],"latest":latest,"automatic_retry":False}
  adapter.record("verified",result)
  return result
 finally:
  adapter.finish()
