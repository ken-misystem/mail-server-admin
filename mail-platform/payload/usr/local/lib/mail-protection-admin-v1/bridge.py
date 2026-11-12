"""Fixed operations added to the authenticated Unix broker."""
import re
from policy import exact, require
from store import SettingsStore


class ProtectionBridge:
    def __init__(self, previous, connection, directory, clock):
        self.previous = previous
        self.directory = directory
        self.settings = SettingsStore(connection, self.authorize, clock)

    def authorize(self, actor, epoch):
        require(type(actor) is str and re.fullmatch(r'[1-9][0-9]{0,19}', actor) and 0 < int(actor) < 2**64, "actor_id")
        require(type(epoch) is str and re.fullmatch(r'[1-9][0-9]{0,19}', epoch) and 0 < int(epoch) < 2**64, "actor_epoch")
        with self.directory.cursor() as cursor:
            cursor.execute(
                "SELECT active,is_system_admin,auth_epoch FROM mail_management.mail_admin_users WHERE id=%s LIMIT 2",
                (actor,)
            )
            rows = cursor.fetchall()
        require(len(rows) == 1 and rows[0][0] == 1 and rows[0][1] == 1 and str(rows[0][2]) == epoch, "actor_session_changed")

    def handle(self, request, *, peer="frontend"):
        require(type(request) is dict, "request_shape")
        operation = request.get("operation")
        if operation not in ("protection.read", "protection.save"):
            return self.previous.handle(request, peer=peer)
        require(peer == "frontend", "protection_frontend_required")
        if operation == "protection.read":
            exact(request, ("operation", "actor", "epoch", "kind"))
            return self.settings.read(request["actor"], request["epoch"], request["kind"])
        exact(request, ("operation", "actor", "epoch", "kind", "revision", "payload", "credential", "request_id"))
        return self.settings.save(request["actor"], request["epoch"], request["kind"], request["revision"],
                                  request["payload"], request["credential"], request["request_id"])

    def start(self):
        return self.previous.start()
