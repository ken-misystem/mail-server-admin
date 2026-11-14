"""Limited RCPT endpoint for a signed, monotonic secondary recipient registry."""
import argparse
import asyncio
import json
from pathlib import Path
import os
import socket
import struct

from secondary_mx import adopt, recipient_action


class Policy:
    def __init__(self, snapshot, signature, key, state, allowed_uid):
        self.snapshot = Path(snapshot)
        self.signature = Path(signature)
        self.key = Path(key)
        self.state = Path(state)
        self.allowed_uid = allowed_uid
        self.cached_identity = None
        self.cached_value = None

    def read(self):
        info = self.snapshot.lstat()
        signature = self.signature.lstat()
        key = self.key.lstat()
        identity = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns,
                    signature.st_ino, signature.st_mtime_ns, signature.st_ctime_ns,
                    key.st_ino, key.st_mtime_ns, key.st_ctime_ns)
        if identity != self.cached_identity:
            value = adopt(self.snapshot, self.signature, self.key, self.state)
            self.cached_value = value
            self.cached_identity = identity
        return self.cached_value

    async def handle(self, reader, writer):
        try:
            raw_peer = writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            if struct.unpack('3i', raw_peer)[1] != self.allowed_uid:
                return
            raw = await asyncio.wait_for(reader.readuntil(b'\n\n'), 3)
            if len(raw) > 65536:
                return
            fields = dict(line.split('=', 1) for line in raw.decode('utf-8').strip().split('\n'))
            if fields.get('request') != 'smtpd_access_policy':
                return
            try:
                action = recipient_action(self.read(), fields.get('recipient'))
            except (OSError, ValueError):
                action = '451 4.3.5 Recipient registry unavailable'
            writer.write(('action='+action+'\n\n').encode())
            await writer.drain()
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()


async def serve(args):
    if os.path.lexists(args.socket):
        raise ValueError('secondary_socket_exists')
    policy = Policy(args.snapshot, args.signature, args.key, args.state, args.allowed_uid)
    server = await asyncio.start_unix_server(policy.handle, str(args.socket), limit=65536)
    os.chown(args.socket, -1, args.socket_gid)
    os.chmod(args.socket, 0o660)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    for name in ('snapshot', 'signature', 'key', 'state', 'socket'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--allowed-uid', type=int, required=True)
    parser.add_argument('--socket-gid', type=int, required=True)
    asyncio.run(serve(parser.parse_args()))
