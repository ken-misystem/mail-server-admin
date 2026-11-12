"""Only our managed fragment changes; preserve baseline exceptions and known rollback."""
import hashlib,json
from runtime_files import read,write,encoded
from spam_config import render,verify_effective,parse_owned_fragment
from forwarding import need

def apply(path,desired,domains,aliases,legacy_pin,expected_current,capture,command,history):
    raw,rules=render(desired,domains,aliases);old,meta=read(path,mode=0o644);need(meta['sha256']==expected_current,'spam_managed_file_drift')
    actual=json.loads(command('settings',capture));verify_effective(actual,parse_owned_fragment(old),legacy_pin)
    if raw==old:
        verify_effective(actual,rules,legacy_pin);return {'state':'file_validated','fragment_sha256':meta['sha256'],'reload_requested':False,'rules':len(rules),'message_matching_verified':False}
    # History contains public scores/domain conditions, never old secret settings.
    history({'before_sha256':meta['sha256'],'after_sha256':hashlib.sha256(raw).hexdigest()},old,raw)
    pin=write(path,raw,group=meta['gid'],mode=0o644,prior_pin=expected_current);reload_attempted=False
    try:
        out=command('rspamd_check',capture);need(out.strip()in (b'syntax OK',b'config OK',b''),'rspamd_check_unclassified_output')
        reload_attempted=True;command('rspamd_reload',capture)
        actual=json.loads(command('settings',capture));verify_effective(actual,rules,legacy_pin)
        return {'state':'file_validated_reload_requested','fragment_sha256':pin,'reload_requested':True,'rules':len(rules),'message_matching_verified':False}
    except BaseException:
        # Unknown changes are never overwritten; a failing recovery is retained as a failure.
        write(path,old,group=meta['gid'],mode=0o644,prior_pin=pin)
        check=command('rspamd_check',capture);need(check.strip()in (b'syntax OK',b'config OK',b''),'rspamd_recovery_check_unclassified')
        if reload_attempted:command('rspamd_reload',capture)
        raise
