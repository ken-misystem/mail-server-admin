"""Bounded native failure metadata; never return arbitrary diagnostic text."""
from hashlib import sha256
import re

def native_failure(raw,exit_status):
    text=raw.decode('utf-8','replace')
    module=re.search(r"ModuleNotFoundError: No module named '([A-Za-z0-9_.]{1,100})'",text)
    lines=re.findall(r'File "[^"\n]*/([A-Za-z0-9_.-]{1,100}\.py)", line ([0-9]+)',text)
    classes=re.findall(r'(?m)^([A-Za-z][A-Za-z0-9_]{0,70}(?:Error|Exception)):',text)
    return {'native_exit':exit_status,'stderr_bytes':len(raw),'stderr_sha256':sha256(raw).hexdigest(),
        'missing_module':module[1]if module else None,'exception_class':classes[-1]if classes else None,
        'public_frames':[{'source':n,'line':int(v)}for n,v in lines[-8:]],
        'markers':{k:v in text.lower()for k,v in {'permission':'permission denied','memory':'cannot allocate memory',
            'configuration':'configuration error','unavailable':'service unavailable','tls':'tls error',
            'socket':'cannot connect','fatal':'fatal:','panic':'panic:'}.items()},'raw_error_saved':False}
