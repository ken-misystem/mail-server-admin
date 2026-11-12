import tempfile,json
from pathlib import Path
from updater import save,run_update
from release import ReleaseError
with tempfile.TemporaryDirectory()as t:
 p=Path(t);save(p/'transaction.json',{'phase':'rolled_back','version':'1.0.0'})
 before=(p/'transaction.json').read_bytes()
 try:run_update(p,p/'nonexistent',{'version':'1.0.0'},'unused',p/'no-key');raise AssertionError('failed version repeated')
 except ReleaseError as e:assert str(e)=='previous_release_failed_requires_review'
 assert (p/'transaction.json').read_bytes()==before and not(p/'installed.json').exists()
 print(json.dumps({'status':'pass','new_checks':['failed_release_not_retried','prior_failure_record_preserved'],'old_native_suite_reexecuted':False}))
