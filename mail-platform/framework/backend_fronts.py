"""Connect the certificate gate to enrolled stable Unix frontends."""
import os
import re
from pathlib import PurePosixPath
import socket

from network_guard import need
from transport import unix_peer

PROTOCOLS = frozenset(('submission', 'imaps', 'pop3s'))


class StableBackend:
    def __init__(self, original, endpoints):
        need(type(endpoints) is dict and set(endpoints) == PROTOCOLS,
             'backend_front_protocols')
        self.original = original
        self.endpoints = {}
        for protocol, value in endpoints.items():
            need(type(value) is dict and set(value) == {'path', 'uid'}, 'backend_front_fields')
            path = value['path']
            need(type(path) is str and path.startswith('/run/mail-platform-')
                 and re.fullmatch('/[A-Za-z0-9_./-]+',path) is not None
                 and str(PurePosixPath(path)) == path and '..' not in path.split('/')
                 and '\x00' not in path and len(os.fsencode(path)) < 108,
                 'backend_front_path')
            need(type(value['uid']) is int and value['uid'] >= 0, 'backend_front_uid')
            self.endpoints[protocol] = (path, value['uid'])
        need(len({value[0] for value in self.endpoints.values()}) == 3,
             'backend_front_alias')

    def open(self, protocol, identity, source, destination):
        need(protocol in self.endpoints, 'backend_front_protocol')
        self.original.scope.verify()
        self.original.inventory.current(protocol, source, destination)
        path, uid = self.endpoints[protocol]
        channel = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            channel.settimeout(5)
            channel.connect(path)
            unix_peer(channel, uid)
            self.original.scope.verify()
            self.original.inventory.current(protocol, source, destination)
            return channel
        except BaseException:
            channel.close()
            raise


def select(original, endpoints):
    if endpoints is None:
        return original
    return StableBackend(original, endpoints)
