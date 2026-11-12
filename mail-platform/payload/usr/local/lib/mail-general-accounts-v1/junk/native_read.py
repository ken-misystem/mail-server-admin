"""Bounded counter diagnostics. No raw stdout/stderr is persisted or exported."""
import subprocess
import threading

ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C'}
MARKERS = {
    'permission_denied': (b'permission denied', b'operation not permitted'),
    'uid_switch_failed': (b'setuid', b'seteuid', b'setresuid', b'unable to change uid'),
    'gid_switch_failed': (b'setgid', b'setgroups', b'setresgid'),
    'user_unknown': (b'unknown user', b'user not found', b'userdb lookup failed'),
    'mailbox_missing': (b'mailbox doesn\'t exist', b'mailbox not found', b'mailbox does not exist'),
    'storage_failure': (b'no space left on device', b'read-only file system', b'i/o error'),
    'connection_failure': (b'connection refused', b'connection timed out', b'connection reset'),
    'unsupported_option': (b'unknown option', b'unrecognized option'),
}


class Reader:
    def __init__(self, account, factory=subprocess.Popen):
        self.account = account
        self.factory = factory
        self.last = None

    def __call__(self, command, *, byte_limit, timeout):
        # Only the existing three counter commands, not caller-supplied programs.
        argv = list(command)
        prefix = ['/usr/bin/doveadm']
        kind = None
        if argv == prefix + ['mailbox', 'list', '-u', self.account, 'Junk']:
            kind = 'list'
        elif argv == prefix + ['-f', 'flow', 'mailbox', 'status', '-u', self.account, '-t', 'messages', 'Junk']:
            kind = 'status'
        elif (len(argv) == 12 and argv[:9] == prefix + ['-f', 'flow', 'search', '-u', self.account, 'mailbox', 'Junk', 'SAVEDSINCE']
              and argv[10] == 'SAVEDBEFORE' and argv[9].isdigit() and argv[11].isdigit()
              and 1000000000 <= int(argv[9]) < int(argv[11]) <= 9999999999):
            kind = 'search'
        if kind is None or (byte_limit, timeout) != ((1048576, 30) if kind == 'search' else (256, 10)):
            raise ValueError('counter_native_scope')
        buffers = [bytearray(), bytearray()]
        overflow = threading.Event()
        io_error = threading.Event()
        p = None
        detail = dict(command=kind, exit=None, errno=None, error_class=None, timed_out=False,
                      output_bound=False, io_error=False, stdout_bytes=0, stderr_bytes=0,
                      stderr_classified=False, markers={}, stdout_shape='unavailable')
        try:
            p = self.factory(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=ENV, cwd='/', close_fds=True, bufsize=0)

            def drain(index, stream, bound):
                try:
                    while True:
                        chunk = stream.read(4096)
                        if not chunk:
                            break
                        room = bound - len(buffers[index])
                        buffers[index].extend(chunk[:max(0, room)])
                        if len(chunk) > room:
                            overflow.set(); p.kill(); break
                except (OSError, ValueError):
                    io_error.set()

            threads = [threading.Thread(target=drain, args=(i, s, b), daemon=True)
                       for i, (s, b) in enumerate(((p.stdout, byte_limit), (p.stderr, 8192)))]
            for thread in threads:
                thread.start()
            try:
                p.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                detail['timed_out'] = True; p.kill(); p.wait(timeout=2)
            for thread in threads:
                thread.join(timeout=2)
            detail['io_error'] = io_error.is_set() or any(t.is_alive() for t in threads)
            detail['exit'] = p.returncode
            detail['output_bound'] = overflow.is_set()
            out, err = map(bytes, buffers)
            detail.update(stdout_bytes=len(out), stderr_bytes=len(err))
            lowered = err.lower()
            detail['markers'] = {name: any(token in lowered for token in tokens) for name, tokens in MARKERS.items()}
            detail['stderr_classified'] = not err or any(detail['markers'].values())
            detail['stdout_shape'] = ('exact_junk' if out == b'Junk\n' else 'empty' if not out else 'other') if kind == 'list' else 'not_exported'
            return out if p.returncode == 0 and not any(detail[k] for k in ('timed_out', 'output_bound', 'io_error')) else None
        except (OSError, subprocess.SubprocessError) as error:
            detail.update(error_class=type(error).__name__, errno=getattr(error, 'errno', None))
            return None
        finally:
            if p is not None:
                if p.poll() is None:
                    p.kill(); p.wait(timeout=2)
                for stream in (p.stdout, p.stderr):
                    stream.close()
            self.last = detail
