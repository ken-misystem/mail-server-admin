"""Render only validated constant values into the reviewed fixed Lua source."""
import json
from pathlib import Path
from policy import validate


def render_attachment(payload):
    value = validate("scanner", payload)
    extensions = "{" + ",".join(json.dumps(item) for item in value["extensions"]) + "}"
    config = "{extensions=" + extensions + ",attachment_action=" + json.dumps(value["attachment_action"])
    config += ",encrypted_archives=" + ("true" if value["encrypted_archives"] else "false") + "}"
    template = Path(__file__).with_name("attachment.lua").read_text(encoding="utf-8")
    if template.count("__MAIL_ADMIN_CONFIG__") != 1:
        raise ValueError("attachment_template_binding")
    return template.replace("__MAIL_ADMIN_CONFIG__", config).encode()
