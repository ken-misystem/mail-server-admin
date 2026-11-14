"""Stable Unix frontend. Pin streams or complete policy requests to one generation."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import secrets
import socket
import stat
import struct
import signal

from host_transaction import regular

FAILURE = b'action=451 4.3.5 Update backend unavailable\n\n'
NONCE_FIELD = b'mail_platform_generation_nonce'


def read_route(path):
    raw, attributes = regular(path, 16384)
    if attributes['uid'] != 0 or attributes['mode'] & 0o022:
        raise ValueError('route_owner_or_permissions')
    value = json.loads(raw)
    if set(value) != {'generation', 'socket'}:
        raise ValueError('route_fields')
    if not isinstance(value['generation'], str) or not value['generation'].isalnum():
        raise ValueError('route_generation')
    target = Path(value['socket'])
    if not target.is_absolute() or '..' in target.parts or '\x00' in str(target):
        raise ValueError('route_socket')
    return value


class Front:
    def __init__(self, route, mode, allowed_uid, capacity=32, wait=1.0, timeout=30.0, policy_nonce=False):
        if mode not in ('stream', 'policy') or not 1 <= capacity <= 1024:
            raise ValueError('front_configuration')
        self.route = Path(route)
        self.mode = mode
        self.allowed_uid = allowed_uid
        self.capacity = capacity
        self.wait = wait
        self.timeout = timeout
        if policy_nonce and mode != 'policy':
            raise ValueError('front_policy_nonce_mode')
        self.policy_nonce = policy_nonce
        self.admission = asyncio.Event()
        self.admission.set()
        self.active = {}
        self.pending = 0
        self.connections = 0

    @staticmethod
    def peer(writer):
        raw = writer.get_extra_info('socket').getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        return struct.unpack('3i', raw)[1]

    async def acquire(self):
        if self.pending + sum(self.active.values()) >= self.capacity:
            raise ValueError('front_capacity')
        self.pending += 1
        try:
            deadline = asyncio.get_running_loop().time() + self.wait
            while True:
                await asyncio.wait_for(self.admission.wait(), max(0, deadline - asyncio.get_running_loop().time()))
                if self.admission.is_set():
                    break
            route = read_route(self.route)
            generation = route['generation']
            self.active[generation] = self.active.get(generation, 0) + 1
            return route
        finally:
            self.pending -= 1

    def release(self, route):
        generation = route['generation']
        self.active[generation] -= 1
        if self.active[generation] == 0:
            del self.active[generation]

    @staticmethod
    async def close(writer):
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

    async def policy(self, reader, writer):
        # Survives backend handoff, while each new SMTP policy connection is distinct.
        nonce = secrets.token_hex(32).encode() if self.policy_nonce else None
        while True:
            try:
                request = await asyncio.wait_for(reader.readuntil(b'\n\n'), self.timeout)
            except asyncio.IncompleteReadError:
                return
            if len(request) > 65536:
                raise ValueError('policy_packet_size')
            route = None
            backend = None
            try:
                forwarded = request
                if nonce is not None:
                    if any(line.startswith(NONCE_FIELD+b'=') for line in request.split(b'\n')):
                        raise ValueError('front_nonce_supplied_by_caller')
                    forwarded = request[:-1]+NONCE_FIELD+b'='+nonce+b'\n\n'
                    if len(forwarded)>32768:
                        raise ValueError('front_nonce_packet_bound')
                route = await self.acquire()
                source, backend = await asyncio.wait_for(asyncio.open_unix_connection(route['socket'], limit=65536), self.wait)
                backend.write(forwarded)
                await backend.drain()
                reply = await asyncio.wait_for(source.readuntil(b'\n\n'), self.timeout)
                if len(reply) > 65536 or not reply.startswith(b'action='):
                    raise ValueError('policy_reply')
            except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
                # A failed write/read is never replayed to another generation.
                reply = FAILURE
            finally:
                try:
                    if backend:
                        await self.close(backend)
                finally:
                    if route:
                        self.release(route)
            writer.write(reply)
            await writer.drain()

    async def stream(self, reader, writer):
        route = await self.acquire()
        backend = None
        copies = []
        try:
            source, backend = await asyncio.wait_for(asyncio.open_unix_connection(route['socket']), self.wait)

            async def copy(source_reader, destination):
                while True:
                    data = await source_reader.read(65536)
                    if not data:
                        if destination.can_write_eof():
                            destination.write_eof()
                        return
                    destination.write(data)
                    await destination.drain()

            copies = [asyncio.create_task(copy(reader, backend)), asyncio.create_task(copy(source, writer))]
            await asyncio.gather(*copies)
        finally:
            for task in copies:
                if not task.done():
                    task.cancel()
            try:
                await asyncio.gather(*copies, return_exceptions=True)
                if backend:
                    await self.close(backend)
            finally:
                self.release(route)

    async def client(self, reader, writer):
        counted = False
        try:
            if self.peer(writer) != self.allowed_uid or self.connections >= self.capacity:
                return
            self.connections += 1
            counted = True
            if self.mode == 'policy':
                await self.policy(reader, writer)
            else:
                await self.stream(reader, writer)
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            if counted:
                self.connections -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def control(self, reader, writer):
        try:
            if self.peer(writer) != 0:
                return
            raw = await asyncio.wait_for(reader.readline(), 2)
            request = json.loads(raw)
            if request not in ({'operation': 'status'}, {'operation': 'pause'}, {'operation': 'resume'}):
                raise ValueError('control_request')
            if request['operation'] == 'pause':
                self.admission.clear()
            if request['operation'] == 'resume':
                self.admission.set()
            reply = {'pid': os.getpid(), 'accepting': self.admission.is_set(),
                     'active': dict(self.active), 'pending': self.pending}
            writer.write(json.dumps(reply).encode() + b'\n')
            await writer.drain()
        except (OSError, ValueError, asyncio.TimeoutError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()


def control(path, operation):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(3)
        connection.connect(str(path))
        connection.sendall(json.dumps({'operation': operation}).encode() + b'\n')
        response = bytearray()
        while not response.endswith(b'\n') and len(response) < 16384:
            data = connection.recv(4096)
            if not data:
                break
            response.extend(data)
    reply = json.loads(response)
    if set(reply) != {'pid', 'accepting', 'active', 'pending'}:
        raise ValueError('control_response')
    return reply


async def serve(args, ready=None):
    read_route(args.route)
    front = Front(args.route, args.mode, args.allowed_uid, args.capacity, args.wait, args.timeout, args.policy_nonce)
    activated = getattr(args, 'activated', False)
    # Both socket paths are supplied by the root-owned installed unit.
    for path in (args.listen, args.control):
        if os.path.lexists(path) and not (activated and path == args.listen):
            raise ValueError('socket_path_exists')
        if not path.parent.is_dir() or path.parent.is_symlink():
            raise ValueError('socket_parent')
    if activated:
        if os.environ.get('LISTEN_PID') != str(os.getpid()) or os.environ.get('LISTEN_FDS') != '1':
            raise ValueError('front_socket_activation')
        listener = socket.socket(fileno=3)
        if listener.family != socket.AF_UNIX or listener.getsockname() != str(args.listen):
            raise ValueError('front_activated_socket_scope')
        client = await asyncio.start_unix_server(front.client, sock=listener, limit=65536, cleanup_socket=False)
    else:
        client = await asyncio.start_unix_server(front.client, str(args.listen), limit=65536, cleanup_socket=True)
    private = await asyncio.start_unix_server(front.control, str(args.control), limit=16384, cleanup_socket=True)
    if not activated:
        os.chmod(args.listen, 0o660)
        if args.listen_gid is not None:
            os.chown(args.listen, -1, args.listen_gid)
    os.chmod(args.control, 0o600)
    async with client, private:
        if ready is not None:
            ready()
        await asyncio.gather(client.serve_forever(), private.serve_forever())


async def configured_fronts(values):
    task = asyncio.current_task()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
    remaining = len(values)
    def ready():
        nonlocal remaining
        remaining -= 1
        address = os.environ.get('NOTIFY_SOCKET')
        if remaining == 0 and address:
            if address.startswith('@'):
                address = '\0'+address[1:]
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
                channel.connect(address)
                channel.sendall(b'READY=1')
    try:
        await asyncio.gather(*(serve(value, ready) for value in values))
    except asyncio.CancelledError:
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--configuration', type=Path)
    parser.add_argument('--route', type=Path)
    parser.add_argument('--listen', type=Path)
    parser.add_argument('--control', type=Path)
    parser.add_argument('--mode', choices=('stream', 'policy'))
    parser.add_argument('--allowed-uid', type=int)
    parser.add_argument('--listen-gid', type=int)
    parser.add_argument('--capacity', type=int, default=32)
    parser.add_argument('--wait', type=float, default=1.0)
    parser.add_argument('--timeout', type=float, default=30.0)
    parser.add_argument('--policy-nonce', action='store_true')
    parser.add_argument('--activated', action='store_true')
    arguments = parser.parse_args()
    values = [arguments]
    if arguments.configuration:
        raw, metadata = regular(arguments.configuration, 16384)
        if metadata['uid'] != 0 or metadata['mode'] & 0o022:
            raise ValueError('front_configuration_trust')
        config = json.loads(raw)
        required = {'route', 'listen', 'control', 'mode', 'allowed_uid'}
        if type(config) is not list or not 1 <= len(config) <= 8:
            raise ValueError('front_configuration_inventory')
        values = []
        for item in config:
            if type(item) is not dict or set(item) != required or item['mode'] != 'stream' or type(item['allowed_uid']) is not int or item['allowed_uid'] < 0:
                raise ValueError('front_configuration_fields')
            current = argparse.Namespace(**vars(arguments))
            for name, value in item.items():
                if name in ('route', 'listen', 'control'):
                    if type(value) is not str or not value.startswith('/') or '..' in Path(value).parts:
                        raise ValueError('front_configuration_path')
                    value = Path(value)
                setattr(current, name, value)
            values.append(current)
    if any(value.route is None or value.listen is None or value.control is None or value.mode is None or value.allowed_uid is None for value in values):
        raise ValueError('front_required_arguments')
    asyncio.run(configured_fronts(values))


if __name__ == '__main__':
    main()
