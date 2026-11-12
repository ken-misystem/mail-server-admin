"""Uninstalled PyMySQL role connector, exact private held FD and endpoint only.

No endpoint defaults, network fallback, credential emission, package installation,
driver discovery at import, automatic runtime arming or connection retry.
"""
from dataclasses import dataclass
import json
import os
import re
import stat
import sys
from compat import AdapterError, require
from database import failure


@dataclass(frozen=True)
class Endpoint:
    unix_socket: str
    user: str
    database: str

    def valid(self):
        # A reviewed deployment manifest supplies the socket; never browser input.
        return (type(self.unix_socket) is str and self.unix_socket.startswith('/')
            and not any(p in ('', '.', '..') for p in self.unix_socket.split('/')[1:])
            and len(self.unix_socket.encode()) <= 107
            and not any(c.isspace() or ord(c) < 33 for c in self.unix_socket)
            and type(self.user) is str and re.fullmatch('[a-z][a-z0-9_]{2,31}', self.user) is not None
            and self.user not in {'root','mailpop','adminuser','www_data'}
            and self.database == 'mail_management')


def driver():
    import pymysql  # Imported only after runtime/FD/endpoint guards pass.
    return pymysql


def file_identity(metadata):
    # pread can update atime. Compare held-file identity and change timestamps,
    # not access metadata. Missing fields fail rather than weakening the guard.
    return tuple(getattr(metadata, field) for field in (
        'st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


class RoleConnector:
    def __init__(self, config_fd, runtime, endpoint, *, driver_provider=driver):
        require(type(config_fd) is int and config_fd >= 0 and type(endpoint) is Endpoint and endpoint.valid(),
                'role_connector_shape', 'connector_init')
        self.config_fd, self.runtime, self.endpoint, self.driver_provider = config_fd, runtime, endpoint, driver_provider

    def __call__(self):
        self.runtime.require_armed()  # Before credential FD read or driver import.
        require(sys.platform == 'linux', 'linux_runtime_required', 'db_connect')
        raw = data = None
        phase = 'private_fd_metadata'
        try:
            before = os.fstat(self.config_fd)
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid == os.geteuid() and before.st_mode & 0o077 == 0
                    and 0 < before.st_size <= 8192, 'private_config_metadata', phase)
            raw = os.pread(self.config_fd, before.st_size + 1, 0)
            require(len(raw) == before.st_size and file_identity(os.fstat(self.config_fd)) == file_identity(before),
                    'private_config_drift', phase)
            phase = 'private_fd_shape'
            data = json.loads(raw)
            require(type(data) is dict and set(data) == {'unix_socket','user','password','database'}
                    and all(type(v) is str and 0 < len(v) <= 1024 and '\x00' not in v for v in data.values()),
                    'private_config_shape', phase)
            require((data['unix_socket'],data['user'],data['database']) ==
                    (self.endpoint.unix_socket,self.endpoint.user,self.endpoint.database),
                    'private_endpoint_mismatch', phase)
            phase = 'driver_import'; api = self.driver_provider()
            phase = 'driver_connect'
            return api.connect(**data, charset='utf8mb4', autocommit=False,
                cursorclass=api.cursors.Cursor, connect_timeout=5, read_timeout=5, write_timeout=5,
                local_infile=False, client_flag=0)
        except AdapterError: raise
        except Exception as error: raise failure(error, phase) from error
        finally:
            # Drop references only. Python strings are not claimed to be securely wiped.
            if type(data) is dict: data.clear()
            raw = data = None

