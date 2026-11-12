"""Fixed-path publication adapter. Reuses the already native-verified journal.
New managed files must first be provisioned as empty files by the approved
installer; this adapter never creates arbitrary target paths or deletes mail.
"""
import hashlib,re
from pathlib import Path
import sys
D=Path(__file__).resolve().parent
sys.path.insert(0,str(D.parent))
from policy import validate
from render import upstream_fragments
from runtime_render import guard,attachments
from backend_companion import PROFILE,compose

TARGETS={
 "scanner":("/etc/rspamd/lua.local.d/90-mail-protection-v1.lua","/var/lib/mail-protection-public-v1/antivirus.lua","/var/lib/mail-protection-public-v1/attachments.lua"),
 "upstream":("/etc/postfix/main.cf","/etc/postfix/master.cf","/etc/postfix/mail-admin-upstream-passwords","/etc/mail-client-certificates-v1/postfix/main.cf","/etc/mail-client-certificates-v1/postfix/master.cf","/etc/mail-client-certificates-v1/postfix/mail-admin-upstream-passwords",PROFILE)}
PARAMETERS=("relayhost","default_transport","relay_transport")
LOADER=b'\n-- mail-admin-protection-v1\nlocal marker_parent=rspamd_config:register_symbol({name="MAIL_ADMIN_PROTECTION_CHECK",type="callback",callback=function() return false end})\nrspamd_config:register_symbol({name="MAIL_ADMIN_PROTECTION_LOADED",type="virtual",score=0,parent=marker_parent})\ndofile("/var/lib/mail-protection-public-v1/antivirus.lua")\ndofile("/var/lib/mail-protection-public-v1/attachments.lua")\n'

def need(value,reason):
    if not value:raise ValueError(reason)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def patch_main(raw,values):
    need(type(raw)is bytes and len(raw)<=2097152 and b"\0"not in raw and b"\r"not in raw,"postfix_source_shape")
    need(set(values)==set(PARAMETERS) and all(type(v)is str and not any(c in v for c in "\r\n\0")for v in values.values()),"owned_main_parameters")
    lines=raw.splitlines(keepends=True);headers=[]
    for i,line in enumerate(lines):
        if not line.strip()or line.lstrip().startswith(b"#")or line[:1]in(b" ",b"\t"):continue
        found=re.match(rb"([A-Za-z0-9_]+)\s*=",line);need(found is not None,"postfix_parameter_line");headers.append((i,found[1].decode()))
    changes={};seen=set()
    for position,(start,name)in enumerate(headers):
        if name not in values:continue
        need(name not in seen,"duplicate_owned_parameter");seen.add(name)
        end=headers[position+1][0]if position+1<len(headers)else len(lines)
        changes[start]=(name+" = "+values[name]+"\n").encode()
        for i in range(start+1,end):
            if lines[i].strip()and not lines[i].lstrip().startswith(b"#")and lines[i][:1]in(b" ",b"\t"):changes[i]=b""
    result=b"".join(changes.get(i,line)for i,line in enumerate(lines))
    if result and not result.endswith(b"\n"):result+=b"\n"
    for name in PARAMETERS:
        if name not in seen:result+=(name+" = "+values[name]+"\n").encode()
    return result
def patch_master(raw,fragment):
    need(type(raw)is bytes and b"\r"not in raw and b"\0"not in raw,"master_source_shape")
    lines=raw.splitlines(keepends=True);starts=[i for i,l in enumerate(lines)if l.strip()and not l.lstrip().startswith(b"#")and l[:1]not in(b" ",b"\t")]
    owned=[]
    for n,i in enumerate(starts):
        fields=lines[i].split()
        if fields[:2]==[b"mail-admin-upstream",b"unix"]:owned.append((i,starts[n+1]if n+1<len(starts)else len(lines)))
    need(len(owned)<=1,"duplicate_owned_transport")
    if owned:
        first,last=owned[0];raw=b"".join(lines[:first]+[l for l in lines[first+1:last]if l.lstrip().startswith(b"#")]+lines[last:])
    if fragment:
        need(fragment.splitlines()[0]==b"mail-admin-upstream unix - - n - - smtp","owned_transport_name")
        raw+=b""if not raw or raw.endswith(b"\n")else b"\n";raw+=fragment
    return raw

class PublicationAdapter:
    """runner owns fixed validate/reload/verify commands; no HTTP-supplied argv."""
    def __init__(self,journal,read,runner,baseline,expected,loader_base):
        self.journal=journal;self.read=read;self.runner=runner
        self.baseline=baseline;self.expected=expected;self.loader_base=loader_base
        self.candidates={};self.touched={}
    def preflight(self,kind,desired,credential):
        need(kind in TARGETS,"publication_kind");validate(kind,desired["payload"])
        need(self.runner.lock_held(),"publication_lock_required")
        need(set(self.expected[kind])==set(TARGETS[kind]),"target_pin_inventory")
        for path,pin in self.expected[kind].items():
            raw=self.read(Path(path));need(digest(raw)==pin,"configuration_changed")
        # Required native/deployment facts are checked by the fixed runner.
        self.runner.prerequisites(kind,desired)
    def prepare(self,kind,desired,credential):
        paths=TARGETS[kind]
        if kind=="scanner":
            current=self.read(Path(paths[0]))
            need(current in(self.loader_base,self.loader_base+LOADER),"unknown_lua_loader")
            values=(self.loader_base+LOADER,guard(desired["payload"]["antivirus"]),attachments(desired["payload"]))
            candidate=dict(zip(paths,values))
        else:
            from dual_upstream import prepare
            current={path:self.read(Path(path))for path in paths}
            smtp_paths=paths[:-1]
            candidate=prepare({path:current[path]for path in smtp_paths},self.baseline,desired["payload"],credential,{path:self.expected[kind][path]for path in smtp_paths})
            candidate[PROFILE]=compose(current[PROFILE],current[smtp_paths[3]],current[smtp_paths[4]],candidate[smtp_paths[3]],candidate[smtp_paths[4]])
        self.candidates[kind]=candidate
        need(all(path in TARGETS[kind]for path in candidate),"target_boundary")
        self.runner.review_candidate(kind,candidate)
        return {"kind":kind,"paths":paths,"revision":desired["revision"]}
    def install(self,intent):
        kind=intent["kind"];self.touched[kind]=[]
        for path,raw in self.candidates[kind].items():
            need(digest(self.read(Path(path)))==self.expected[kind][path],"configuration_changed_before_install")
            if digest(raw)!=self.expected[kind][path]:
                self.touched[kind].append(path);self.journal.swap(Path(path),raw)
    def validate(self,kind):self.runner.validate(kind)
    def reload(self,kind):self.runner.reload(kind)
    def verify_effective(self,kind,desired):self.runner.verify_effective(kind,desired,self.candidates[kind])
    def restore_known(self,intent):self.journal.restore(paths=self.touched[intent["kind"]])
    def validate_restored(self,kind):self.runner.validate(kind)
    def verify_restored(self,kind):
        for path,pin in self.expected[kind].items():need(digest(self.read(Path(path)))==pin,"restored_configuration_mismatch")
        self.runner.verify_restored(kind)
    def capture_failure(self,kind,revision,error):self.runner.capture_failure(kind,revision,error)
