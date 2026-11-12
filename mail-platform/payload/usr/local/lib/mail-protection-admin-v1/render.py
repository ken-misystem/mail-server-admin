"""Owned fragments only. The adapter provides fixed paths and CAS restoration."""
from attachment_render import render_attachment
from policy import validate, credential_binding, credential_update

SASL_MAP = "/etc/postfix/mail-admin-upstream-passwords"


def scanner_fragments(payload):
    value = validate("scanner", payload)
    antivirus = ""
    actions = ""
    if value["antivirus"]:
        antivirus = """mail_admin_clamav {
  type = "clamav";
  servers = "/run/clamav/clamd.ctl";
  symbol = "MAIL_ADMIN_VIRUS";
  symbol_fail = "MAIL_ADMIN_VIRUS_FAIL";
  scan_mime_parts = false;
  dynamic_scan = false;
  no_cache = true;
  timeout = 10;
  retransmits = 0;
  action = "reject";
}
"""
        actions = """rules {
  MAIL_ADMIN_SCANNER_FAILURE {
    expression = "MAIL_ADMIN_VIRUS_FAIL";
    action = "soft reject";
    message = "Temporary antivirus failure";
  }
}
"""
    return {"antivirus.conf": antivirus.encode(), "force_actions.conf": actions.encode(),
            "attachments.lua": render_attachment(value)}


def upstream_fragments(payload, secret):
    value = validate("upstream", payload)
    credential_binding(value, secret)
    if value["mode"] == "direct":
        return {"main_values": None, "master_service": b"", "password_map": b""}
    if secret is not None:
        credential_update(dict(secret, action="replace"), None)
    destination = "[" + value["host"] + "]:" + str(value["port"])
    service = ["mail-admin-upstream unix - - n - - smtp",
               "  -o smtp_tls_security_level=secure",
               "  -o smtp_tls_secure_cert_match=nexthop",
               "  -o smtp_tls_policy_maps=",
               "  -o smtp_tls_CAfile=/etc/ssl/certs/ca-certificates.crt",
               "  -o smtp_tls_wrappermode=" + ("yes" if value["tls"] == "implicit" else "no"),
               "  -o smtp_sasl_auth_enable=" + ("yes" if value["authentication"] else "no"),
               "  -o smtp_sasl_password_maps=" + ("texthash:" + SASL_MAP if value["authentication"] else ""),
               "  -o smtp_sasl_security_options=noanonymous,noplaintext",
               "  -o smtp_sasl_tls_security_options=noanonymous,noplaintext",
               "  -o smtp_sasl_tls_verified_security_options=noanonymous"]
    password_map = b""
    if secret is not None:
        password_map = (destination + " " + secret["username"] + ":" + secret["password"] + "\n").encode()
    return {"main_values": {"relayhost": destination, "default_transport": "mail-admin-upstream",
                            "relay_transport": "mail-admin-upstream"},
            "master_service": ("\n".join(service) + "\n").encode(), "password_map": password_map}
