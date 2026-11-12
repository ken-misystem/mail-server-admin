"""Retained authentication failures from the existing immutable log cache; no SQLite."""
import hashlib,json,re
from pathlib import Path
from runtime_files import read
from forwarding import need

MAX_ROWS=20000
MAX_PAGES=801
MAX_BYTES=64*1024*1024
CATEGORIES={'smtp_in','smtp_out','delivery','access','filter','pop','web','security','system'}
LEVELS={'info','warning','error'}

def unique(pairs):
 result={}
 for key,value in pairs:need(key not in result,'event_cache_duplicate_key');result[key]=value
 return result

def decode(raw):return json.loads(raw.decode('utf-8'),object_pairs_hook=unique)

def collect_rows(directory,now_us,*,capture_status=None):
 need(type(now_us)is int and 0<=now_us<=4102444680000000,'event_cache_clock')
 root=Path(directory);now=now_us//1000000;raw,_=read(root/'index.json',mode=0o640,group=113,limit=262144);catalog=decode(raw)
 need(type(catalog)is dict and catalog.get('schema')==1 and type(catalog.get('generated'))is int and now-180<=catalog['generated']<=now+5,'event_cache_stale_or_schema')
 collector=catalog.get('collector');need(auth_source_ready(collector,now),'event_cache_collection_incomplete')
 def finish(rows):
  if capture_status is not None:capture_status({'scope':'retained_auth_failures','generated_at':catalog['generated'],'retained':catalog['retained'],'window_seconds':86400,'retained_data_only':True,'smtp_main_complete':True,'non_smtp_backlog':[v['source']for v in collector['sources']if v['source']!='main'and v.get('backlog')is True]})
  return rows
 need(type(catalog.get('retained'))is int and 0<=catalog['retained']<=MAX_ROWS and catalog.get('retention_limit')==MAX_ROWS,'event_cache_retained_bound')
 version=catalog.get('version');pages=catalog.get('pages');need(type(version)is list and len(version)==3 and version[0]==catalog['retained']and type(pages)is list and len(pages)<=MAX_PAGES,'event_cache_inventory')
 if catalog['retained']==0:need(version==[0,None,None]and pages==[],'event_cache_empty_inventory');return finish([])
 need(type(version[1])is int and type(version[2])is int and 0<version[1]<=version[2]and pages,'event_cache_version')
 total=0;byte_count=0;result=[];last_min=None;hashes=set();observed_low=None;observed_high=None
 for page in pages:
  need(type(page)is dict and set(page)=={'hash','min','max','start','end','categories','levels'},'event_cache_page_schema')
  digest=page['hash'];need(type(digest)is str and re.fullmatch('[a-f0-9]{64}',digest)is not None and digest not in hashes,'event_cache_page_hash_name');hashes.add(digest)
  need(all(type(page[k])is int for k in ('min','max','start','end'))and 0<page['min']<=page['max']and 0<=page['start']<=page['end'],'event_cache_page_bounds')
  need(last_min is None or page['max']<last_min,'event_cache_page_overlap');last_min=page['min']
  need(type(page['categories'])is list and len(page['categories'])==len(set(page['categories']))and set(page['categories'])<=CATEGORIES and type(page['levels'])is list and len(page['levels'])==len(set(page['levels']))and set(page['levels'])<=LEVELS,'event_cache_page_classes')
  raw,_=read(root/'pages'/(digest+'.json'),mode=0o640,group=113,limit=65536);byte_count+=len(raw);need(byte_count<=MAX_BYTES and hashlib.sha256(raw).hexdigest()==digest,'event_cache_page_drift_or_byte_bound')
  rows=decode(raw);need(type(rows)is list and 1<=len(rows)<=25,'event_cache_page_row_bound');ids=[];stamps=[];cats=set();levels=set()
  for row in rows:
   need(type(row)is dict and type(row.get('id'))is int and page['min']<=row['id']<=page['max']and type(row.get('ts'))is int and 0<=row['ts']<=4102444680000000,'event_cache_row_binding')
   need(row.get('category')in CATEGORIES and row.get('level')in LEVELS,'event_cache_row_class');ids.append(row['id']);stamps.append(row['ts']);cats.add(row['category']);levels.add(row['level']);total+=1;need(total<=MAX_ROWS,'event_cache_row_total_bound')
   need(type(row.get('outcome'))is str and len(row['outcome'])<=32 and type(row.get('recipient'))is str and len(row['recipient'])<=254 and type(row.get('queue'))is str and len(row['queue'])<=32,'event_cache_failure_fields')
   if max(0,now_us-86400000000)<=row['ts']<=now_us and row['outcome']=='auth_failed':
    result.append({'id':row['id'],'ts':row['ts'],'data':json.dumps({k:v for k,v in row.items()if k!='id'},separators=(',',':'))})
  need(ids==sorted(set(ids))and ids[0]==page['min']and ids[-1]==page['max']and min(stamps)==page['start']and max(stamps)==page['end']and cats==set(page['categories'])and levels==set(page['levels']),'event_cache_page_metadata_binding')
  observed_low=ids[0]if observed_low is None else min(observed_low,ids[0]);observed_high=ids[-1]if observed_high is None else max(observed_high,ids[-1])
 need(total==catalog['retained']and observed_low==version[1]and observed_high==version[2],'event_cache_complete_inventory')
 result.sort(key=lambda row:(row['ts'],row['id']),reverse=True)
 return finish([(row['ts'],row['data'])for row in result])


def auth_source_ready(collector,now):
 if type(collector)is not dict or collector.get('status')!='ok':return False
 sources=collector.get('sources')
 if type(sources)is not list or not 1<=len(sources)<=3:return False
 rows={}
 for row in sources:
  if type(row)is not dict or row.get('source')not in ('main','worker','roundcube')or row['source']in rows:return False
  rows[row['source']]=row
 return all(row.get('status')=='ok'and row.get('backlog')is False and type(row.get('last_success'))is int and now-180<=row['last_success']<=now+5 for row in (rows.get('main',{}),rows.get('roundcube',{})))
