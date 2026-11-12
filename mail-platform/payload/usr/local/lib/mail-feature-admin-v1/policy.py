"""Typed configuration. Paths, commands and credentials are not public settings."""
import re

KINDS = ("scanner", "upstream")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields), "configuration_fields")


def defaults(kind):
    if kind == "scanner":
        return {"antivirus": False, "extensions": [], "attachment_action": "reject", "encrypted_archives": False}
    if kind == "upstream":
        return {"mode": "direct", "host": "", "port": 587, "tls": "starttls", "authentication": False}
    raise ValueError("configuration_kind")


def validate(kind, value):
    require(kind in KINDS, "configuration_kind")
    exact(value, defaults(kind))
    if kind == "scanner":
        require(type(value["antivirus"]) is bool and type(value["encrypted_archives"]) is bool, "scanner_boolean")
        require(value["attachment_action"] in ("reject", "tag"), "attachment_action")
        extensions = value["extensions"]
        require(type(extensions) is list and len(extensions) <= 128, "extension_count")
        require(all(type(item) is str and re.fullmatch(r"[a-z0-9]{1,16}", item) for item in extensions), "extension_format")
        require(len(set(extensions)) == len(extensions), "extension_duplicate")
        return dict(value, extensions=sorted(extensions))
    require(value["mode"] in ("direct", "relay"), "upstream_mode")
    require(type(value["port"]) is int and value["port"] in (25, 465, 587), "upstream_port")
    require(value["tls"] in ("starttls", "implicit"), "upstream_tls")
    require((value["port"] == 465) == (value["tls"] == "implicit"), "upstream_port_tls")
    require(type(value["authentication"]) is bool, "upstream_authentication")
    host = value["host"]
    require(type(host) is str, "upstream_host")
    if value["mode"] == "direct":
        require(host == "" and not value["authentication"], "direct_configuration")
    else:
        require(len(host) <= 253 and host == host.lower() and "." in host, "upstream_host")
        require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")), "upstream_host")
        require(not all(label.isdecimal() for label in host.split(".")), "upstream_dns_name_required")
    return dict(value)


def credential_update(change, previous):
    """Private values must never be included in receipts or exception messages."""
    require(type(change) is dict and change.get("action") in ("keep", "replace", "clear"), "credential_action")
    if change["action"] in ("keep", "clear"):
        exact(change, ("action",))
        return previous if change["action"] == "keep" else None
    exact(change, ("action", "username", "password"))
    username, password = change["username"], change["password"]
    require(type(username) is str and type(password) is str, "credential_type")
    require(1 <= len(username) <= 256 and 1 <= len(password) <= 512, "credential_length")
    require(all(33 <= ord(char) <= 126 for char in username + password) and ":" not in username, "credential_format")
    return {"username": username, "password": password}


def credential_binding(value, private):
    if value["authentication"]:
        require(private is not None, "credential_required")
    else:
        require(private is None, "credential_clear_required")
