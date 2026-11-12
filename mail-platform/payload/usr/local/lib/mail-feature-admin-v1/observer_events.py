"""Authentication projection from complete immutable retained cache; no SQL."""
from published_auth import collect_rows
from observer_projection import authentication

def collect(path,now_us):
 return authentication(collect_rows(path,now_us),now_us,truncated=False)
