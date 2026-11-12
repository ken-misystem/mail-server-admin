"""Policy for the TLS-terminating gateway path, NOT V1 native-ccert mode.

Native Postfix cannot be assumed to inherit the gateway's certificate fields.
Use a live in-process connection lease created only after the TLS handshake.
The dedicated backend's PROXY address->policy field behavior MUST be verified
before deployment; a missing/mismatched lease always temporarily denies.
"""
from core import AdapterError, require


def decide(raw, sessions, registry, *, peer_verified=False):
    try:
        require(peer_verified is True and type(raw) is bytes and len(raw) <= 32768
                and raw.endswith(b"\n\n") and b"\r" not in raw and b"\x00" not in raw,
                "policy_frame", "gateway_policy")
        fields = {}
        lines = raw[:-2].decode("utf-8", "strict").split("\n")
        require(0 < len(lines) <= 128, "policy_frame", "gateway_policy")
        for line in lines:
            key, equals, value = line.partition("=")
            require(equals == "=" and key not in fields and key.isascii() and key.replace("_", "").isalnum()
                    and len(line.encode()) <= 4096 and all(ord(c)>=32 and ord(c)!=127 for c in value),
                    "policy_frame", "gateway_policy")
            fields[key] = value
        require(fields.get("request") == "smtpd_access_policy"
                and fields.get("policy_context") == "device_certificate_gateway_v1"
                and fields.get("protocol_state") in {"RCPT", "DATA", "END-OF-MESSAGE"},
                "policy_scope", "gateway_policy")
        src = (fields["client_address"], int(fields["client_port"]))
        dst = (fields["server_address"], int(fields["server_port"]))
        require(all(0 < p <= 65535 for p in (src[1],dst[1])), "policy_endpoint", "gateway_policy")
        identity = sessions.resolve_route(src, dst)
        registry.require_active(identity)
        if not fields.get("sasl_username"): return b"action=530 5.7.0 Authentication required\n\n"
        if registry.resolve_login(fields["sasl_username"]) != identity.owner_id:
            return b"action=554 5.7.1 Device account mismatch\n\n"
        return b"action=DUNNO\n\n"
    except Exception:
        # Never trust caller-supplied ccert attributes as an alternative lease.
        return b"action=451 4.3.5 Device authorization unavailable\n\n"
