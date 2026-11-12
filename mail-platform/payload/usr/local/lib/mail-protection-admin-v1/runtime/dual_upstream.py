"""Fixed host/private upstream composition; never changes LMTP or routing maps."""
import hashlib,re
MAIN=("/etc/postfix/main.cf","/etc/mail-client-certificates-v1/postfix/main.cf")
MASTER=("/etc/postfix/master.cf","/etc/mail-client-certificates-v1/postfix/master.cf")
MAP=("/etc/postfix/mail-admin-upstream-passwords","/etc/mail-client-certificates-v1/postfix/mail-admin-upstream-passwords")
TARGETS=tuple(p for i in range(2)for p in(MAIN[i],MASTER[i],MAP[i]))
OWNED=("relayhost","default_transport","relay_transport")
def need(value,label):
    if not value:raise ValueError(label)
def declarations(raw):
    need(type(raw)is bytes and len(raw)<=2097152 and b"\0"not in raw and b"\r"not in raw,"main_source_shape")
    lines=raw.splitlines(keepends=True);heads=[];owned={}
    for i,line in enumerate(lines):
        if not line.strip()or line.lstrip().startswith(b"#")or line[:1]in(b" ",b"\t"):continue
        match=re.match(rb"([A-Za-z0-9_]+)\s*=",line);need(match is not None,"main_assignment")
        heads.append((i,match[1].decode()))
    remove=set()
    for pos,(start,name)in enumerate(heads):
        if name not in OWNED:continue
        need(name not in owned,"duplicate_owned_parameter")
        end=heads[pos+1][0]if pos+1<len(heads)else len(lines)
        indices=[start]+[j for j in range(start+1,end)if lines[j].strip()and not lines[j].lstrip().startswith(b"#")and lines[j][:1]in(b" ",b"\t")]
        owned[name]=b"".join(lines[j]for j in indices);remove.update(indices)
    return b"".join(line for i,line in enumerate(lines)if i not in remove),owned
def restore_declarations(current,baseline):
    remainder,unused=declarations(current);original,prior=declarations(baseline)
    if remainder==original:return baseline
    output=remainder
    if output and not output.endswith(b"\n"):output+=b"\n"
    for name in OWNED:
        if name in prior:
            output+=prior[name]
            if not output.endswith(b"\n"):output+=b"\n"
    return output
def prepare(current,baselines,payload,credential,expected):
    from apply_adapter import patch_main,patch_master
    from render import upstream_fragments
    need(set(current)==set(expected)==set(TARGETS)and set(baselines)==set(MAIN),"dual_instance_inventory")
    for path in TARGETS:need(hashlib.sha256(current[path]).hexdigest()==expected[path],"dual_instance_changed")
    fragments=upstream_fragments(payload,credential);candidate={}
    for i in range(2):
        candidate[MAIN[i]]=restore_declarations(current[MAIN[i]],baselines[MAIN[i]])if fragments["main_values"]is None else patch_main(current[MAIN[i]],fragments["main_values"])
        service=fragments["master_service"].replace(MAP[0].encode(),MAP[i].encode())
        candidate[MASTER[i]]=patch_master(current[MASTER[i]],service)
        candidate[MAP[i]]=fragments["password_map"]
    return candidate
