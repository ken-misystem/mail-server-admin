"""Keep standalone backend startup pins consistent with both owned SMTP files."""
import hashlib,json
PROFILE="/etc/mail-client-certificates-v1/smtpd.json"
def need(v,label):
 if not v:raise ValueError(label)
def compose(raw,old_main,old_master,new_main,new_master):
 value=json.loads(raw)
 need(type(value)is dict and value.get("configuration")=="/etc/mail-client-certificates-v1/postfix"and value.get("postfix_uid")==103 and value.get("postfix_gid")==105,"backend_configuration_identity")
 pin=lambda b:hashlib.sha256(b).hexdigest()
 need(value.get("pins")=={"main.cf":pin(old_main),"master.cf":pin(old_master)},"backend_configuration_pins_changed")
 value["pins"]={"main.cf":pin(new_main),"master.cf":pin(new_master)}
 return(json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
