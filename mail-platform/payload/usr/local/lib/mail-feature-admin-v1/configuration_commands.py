"""Native queries execute as observed Rspamd UID; reload remains the fixed root command."""
import hashlib,re
from configuration_commands_base import run as legacy_run
from native_query import COMMANDS,query,need

def run(name,capture):
 if name not in COMMANDS:return legacy_run(name,capture)
 row,out,err=query(name);capture(row,out,err);need(row['exit']==0 and not row['timeout']and not row['overflow'],'Rspamd_query_failed')
 # Same narrow isolation-cache classification already reviewed. Map errors stay fatal.
 for line in err.decode('utf-8','strict').splitlines():
  need(not re.search(r'\b(?:fatal|panic)\b|cannot open file|map for configuration',line,re.I)and'hyperscan cache'in line.lower()and re.search(r'(?:Permission denied|Read-only file system)\s*$',line),'Rspamd_query_diagnostic')
 return out
