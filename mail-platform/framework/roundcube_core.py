"""Apply the two signed Sieve fixes to trusted OS sources entirely in memory."""
import re
from source_patches import apply

TARGETS={
    'usr/share/roundcube/plugins/managesieve/lib/Roundcube/rcube_sieve_engine.php':'rcube_sieve_engine.php',
    'usr/share/roundcube/plugins/managesieve/lib/Roundcube/rcube_sieve_forward.php':'rcube_sieve_forward.php',
}

def hunks(raw,name):
    lines=raw.decode('utf-8').replace('\r\n','\n').splitlines(keepends=True)
    if lines[:2]!=['--- a/'+name+'\n','+++ b/'+name+'\n']:
        raise ValueError('Roundcube_patch_header')
    result=[]
    before=[]
    after=[]
    expected=None
    for line in lines[2:]+['@@ end\n']:
        if line.startswith('@@'):
            if expected is not None:
                if (len(before),len(after))!=expected:
                    raise ValueError('Roundcube_patch_hunk_length')
                result.append({'before':''.join(before),'after':''.join(after)})
            if line=='@@ end\n':
                break
            match=re.fullmatch(r'@@ -[0-9]+,([0-9]+) \+[0-9]+,([0-9]+) @@\n',line)
            if match is None:
                raise ValueError('Roundcube_patch_hunk_header')
            expected=tuple(int(value) for value in match.groups())
            before=[]
            after=[]
        elif expected is None or line[:1] not in (' ','+','-'):
            raise ValueError('Roundcube_patch_line')
        else:
            if line[0] in (' ','-'):
                before.append(line[1:])
            if line[0] in (' ','+'):
                after.append(line[1:])
    if not result:
        raise ValueError('Roundcube_patch_empty')
    return result

def render(files,read_live):
    output={}
    for target,name in TARGETS.items():
        raw,metadata=read_live('/'+target)
        if metadata['uid']!=0 or metadata['mode']&0o022 or len(raw)>262144:
            raise ValueError('Roundcube_package_source_trust')
        patch=files['integration/roundcube-patches/'+name+'.patch']
        output[target]=apply(target,raw,{target:{'hunks':hunks(patch,name)}})
    return output
