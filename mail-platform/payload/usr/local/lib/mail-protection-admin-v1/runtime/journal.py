"""Fixed-target expected-hash CAS on top of the native-verified atomic/restore engine."""
from pathlib import Path
import read_support as c
from journal_base import Journal as BaseJournal,attrs,atomic
class Journal(BaseJournal):
 def __init__(self,work,expected=None):
  self.expected=dict(expected or{})
  super().__init__(work)
 def swap(self,path,raw):
  path=Path(path);key=str(path);c.need(key in self.expected,"journal_target_not_approved")
  before=attrs(path);old,meta=c.protected(path)
  c.need(attrs(path)==before and meta["sha256"]==self.expected[key],"journal_preimage_changed")
  record={"path":key,"before":before,"before_sha256":c.sha(old),"after_sha256":c.sha(raw),"backup":str(len(self.rows))+".data","state":"intent","after":None}
  c.write(self.work/record["backup"],old);self.rows.append(record);self.save()
  c.need(attrs(path)==before,"journal_CAS_before_swap")
  atomic(path,raw,before["mode"],before["uid"],before["gid"],before["xattrs"],expected=before)
  after=attrs(path);current,metadata=c.protected(path)
  c.need(metadata["sha256"]==record["after_sha256"]and attrs(path)==after,"journal_CAS_after_swap")
  record["after"]=after;record["state"]="applied";self.expected[key]=record["after_sha256"];self.save()
