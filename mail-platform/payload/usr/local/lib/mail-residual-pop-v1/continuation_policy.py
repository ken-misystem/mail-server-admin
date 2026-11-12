"""Strict continuation decisions. No network, import, credentials, or I/O."""
import hashlib,json,re
IDS=(3,4,5,7)
USER3_COUNT=372
USER3_UIDL_SHA="9ce0c4e17390718533028a5d65aad132906ebeccafdebffa8533765ac79726b8"
def need(value,reason):
 if not value:raise ValueError(reason)
def tokens(rows):
 need(isinstance(rows,list)and len(rows)<=200000,"snapshot_bound")
 result=[]
 for index,row in enumerate(rows,1):
  need(isinstance(row,(list,tuple))and len(row)==2 and type(row[0])is int and row[0]==index,"snapshot_numbering")
  value=row[1];need(isinstance(value,str)and re.fullmatch("[!-~]{1,1024}",value)is not None,"snapshot_UIDL")
  result.append(value)
 need(len(set(result))==len(result),"snapshot_duplicate")
 return result
def snapshot(count,size,rows):
 need(type(count)is int and type(size)is int and count>=0 and size>=0,"snapshot_STAT")
 values=tokens(rows);need(count==len(values),"snapshot_count")
 value={"count":count,"size":size,"uidls":values}
 need(len(json.dumps(value,separators=(",",":")).encode())<=16777216,"snapshot_serialized_bound")
 return value
def recover_user3(raw):
 need(isinstance(raw,bytes)and 0<len(raw)<=16777216 and raw.endswith(b"\n"),"saved_log_bound")
 allrows=[json.loads(line)for line in raw.splitlines()if line.strip()]
 starts=[i for i,x in enumerate(allrows)if type(x)is dict and x.get("index")==1];need(starts,"saved_log_no_run")
 rows=allrows[starts[-1]:];need(len(rows)==USER3_COUNT,"saved_log_run_count")
 uidls=tokens([(x.get("index"),x.get("uidl"))for x in rows])
 need(sum(x.get("status")=="import"for x in rows)==87 and sum(x.get("status")=="skip"for x in rows)==285,"saved_log_counters")
 need(hashlib.sha256(json.dumps(uidls,separators=(",",":")).encode()).hexdigest()==USER3_UIDL_SHA,"saved_log_UIDL_drift")
 return uidls
def retained(before,after):
 need(type(before)is dict and type(after)is dict,"snapshot_shape")
 before_ids=set(before["uidls"]);after_ids=set(after["uidls"])
 need(len(before_ids)==before["count"]and len(after_ids)==after["count"],"snapshot_uniqueness")
 need(before_ids<=after_ids,"old_source_UIDL_disappeared")
 return sorted(after_ids-before_ids)
def destination(expected,locations,pop_uidls):
 values=set(expected);need(len(values)==len(expected),"expected_duplicate")
 missing=sorted(u for u in values if not locations.get(u))
 duplicates=sorted(u for u in values if len(locations.get(u,[]))>1)
 inbox={u for u in values if any(box=="INBOX"for box,path in locations.get(u,[]))}
 # POP3 exposes only INBOX. Other folders must remain invisible as well as Junk.
 hidden={u for u in values if locations.get(u)and not any(box=="INBOX"for box,path in locations[u])}
 return {"expected":len(values),"missing":len(missing),"duplicates":len(duplicates),"pop_missing":len(inbox-set(pop_uidls)),"non_INBOX_visible":len(hidden&set(pop_uidls)),"complete":not(missing or duplicates or inbox-set(pop_uidls)or hidden&set(pop_uidls))}
def plan(uid,current_source,locations,original3):
 need(uid in IDS and uid!=1,"fixed_target")
 need(not any(len(locations.get(u,[]))>1 for u in current_source["uidls"]),"destination_duplicate_before")
 missing=[u for u in current_source["uidls"]if not locations.get(u)]
 return {"import_required":bool(missing),"missing_before":len(missing),"old_copies_reused":sum(bool(locations.get(u))for u in current_source["uidls"])}
def summary(raw):
 text=raw.decode("utf-8","strict");result={}
 labels={"imported":"Imported","skipped":"Skipped","missing":"Missing UIDLs","duplicates":"Duplicate UIDLs","pop_missing":"POP3 INBOX UIDL missing","junk_visible":"Junk visible via POP3","source_new_after":"New on old XMail","source_missing_after":"Old snapshot missing"}
 for key,label in labels.items():
  values=re.findall(r"^"+re.escape(label)+r"\s*:\s*([0-9]+)\s*$",text,re.M);need(len(values)==1,"summary_"+key);result[key]=int(values[0])
 need(all(result[k]==0 for k in("missing","duplicates","pop_missing","junk_visible","source_missing_after")),"importer_verification_failed")
 need(len(re.findall(r"^RESULT:\s*PASS\s*$",text,re.M))==1 and len(re.findall(r"^Old XMail snapshot kept:\s*True\s*$",text,re.M))==1,"importer_PASS_missing")
 return result
def release(before,after,account1_before,account1_after,no_target_POP,histories_equal,child_exited):
 need(type(before)is dict and type(after)is dict and set(before)==set(after)=={"version","phase","generation"},"barrier_shape")
 need(type(before["version"])is int and type(after["version"])is int and before["version"]==after["version"]==1 and type(before["generation"])is int and type(after["generation"])is int,"barrier_types")
 need(before["phase"]=="idle"and 0<=before["generation"]<=1000000000 and account1_before==account1_after and no_target_POP and histories_equal and child_exited,"recovery_scope_unknown")
 if before==after:return None
 need(after["phase"]in("migration_in_progress","reconciliation_required")and after["generation"]==before["generation"]+1 and after["generation"]<=1000000000,"unknown_barrier_generation")
 return after|{"phase":"idle"}
