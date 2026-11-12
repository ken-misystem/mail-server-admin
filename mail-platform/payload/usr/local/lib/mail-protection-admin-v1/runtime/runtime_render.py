"""New runtime fragments; previous native13 code and evidence stay immutable."""
import json
from pathlib import Path
D=Path(__file__).resolve().parent
def guard(enabled, socket="/run/clamav/clamd.ctl"):
    if type(enabled)is not bool or socket!="/run/clamav/clamd.ctl":
        raise ValueError("fixed_antivirus_configuration")
    raw=(D/"av_guard.lua").read_text(encoding="utf-8")
    assert raw.count("__ANTIVIRUS_ENABLED__")==1 and raw.count("__CLAMAV_SOCKET__")==1
    return raw.replace("__ANTIVIRUS_ENABLED__","true"if enabled else"false").replace("__CLAMAV_SOCKET__",socket).encode()
def attachments(payload):
    import sys
    sys.path.insert(0,str(D.parent))
    from policy import validate
    value=validate("scanner",payload)
    # Reuse exactly the successful priority-corrected template.
    raw=(D.parent/"native-v2/attachment.lua").read_text(encoding="utf-8")
    config="{extensions={"+",".join(json.dumps(x)for x in value["extensions"])+"},attachment_action="+json.dumps(value["attachment_action"])+",encrypted_archives="+("true"if value["encrypted_archives"]else"false")+"}"
    assert raw.count("__MAIL_ADMIN_CONFIG__")==1
    return raw.replace("__MAIL_ADMIN_CONFIG__",config).encode()
