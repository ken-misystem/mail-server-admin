"""Unchanged validated cache-only diagnostic classifier."""
import hashlib,re
def cache_diagnostics(raw):
 if type(raw)is not bytes or len(raw)>131072:raise ValueError('diagnostic_bound')
 count=0
 for line in raw.decode('utf-8','strict').splitlines():
  # Existing data-map read/open failures must never be accepted as cache warnings.
  if re.search(r'\b(?:fatal|panic)\b|cannot open file|map for configuration',line,re.I)or not ('hyperscan cache'in line.lower() and re.search(r'(?:Permission denied|Read-only file system)\s*$',line)):
   raise ValueError('unexpected_rspamd_diagnostic')
  count+=1
 return {'cache_write_denied':count,'sha256':hashlib.sha256(raw).hexdigest(),'raw_exported':False}
