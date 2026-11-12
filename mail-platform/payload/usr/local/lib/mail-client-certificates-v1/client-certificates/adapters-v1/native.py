"""Linux-only native ports. No main/listener; never invoked by local tests.

Runtime arming is mandatory: verified isolated cgroup with MemorySwapMax=0,
core/dump restrictions, dedicated UID, descriptor-only CA, and exact binary pin.
This module does not pretend Python reference release securely wipes Python strings.
"""
import ctypes
import hashlib
import mmap
import os
import stat
import subprocess
import sys
import threading
import time
import re
from core import AdapterError, require


class LinuxRuntime:
    """Live checks only in the future dedicated worker, not during preparation.

    Exact service cgroup is resolved from /proc/self/cgroup under the kernel ABI
    root, not from a Web argument or an arbitrary supplied 'swap disabled' flag.
    """
    def __init__(self, dedicated_uid):
        require(sys.platform == "linux" and type(dedicated_uid) is int and dedicated_uid > 0,
                "linux_dedicated_uid_required", "runtime")
        self.uid = dedicated_uid

    def harden_self(self):
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        libc = ctypes.CDLL(None, use_errno=True)
        require(libc.prctl(4, 0, 0, 0, 0) == 0, "set_dumpable_failed", "runtime")
        self.require_armed()

    def require_armed(self):
        import resource
        require(os.geteuid() == self.uid, "dedicated_uid_mismatch", "runtime")
        require(resource.getrlimit(resource.RLIMIT_CORE) == (0, 0), "core_limit_required", "runtime")
        libc = ctypes.CDLL(None, use_errno=True)
        require(libc.prctl(3, 0, 0, 0, 0) == 0, "dumpable_process_refused", "runtime")
        status = open("/proc/self/status", "rb").read(32769)
        require(len(status) <= 32768 and b"NoNewPrivs:\t1\n" in status,
                "no_new_privileges_required", "runtime")
        capability = next((line.split(b":",1)[1].strip() for line in status.splitlines() if line.startswith(b"CapEff:")), None)
        require(capability is not None and int(capability, 16) == 0, "capabilities_not_empty", "runtime")
        group = open("/proc/self/cgroup", "rb").read(8193)
        require(len(group) <= 8192 and len(group.splitlines()) == 1 and group.startswith(b"0::/"),
                "unified_cgroup_required", "runtime")
        pieces = group[4:].strip().split(b"/")
        require(all(p and p not in {b".", b".."} for p in pieces), "cgroup_path_shape", "runtime")
        fd = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for piece in pieces:
                new = os.open(piece, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = new
            leaf = os.open("memory.swap.max", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try: require(os.read(leaf, 32).strip() == b"0", "swap_not_disabled", "runtime")
            finally: os.close(leaf)
        finally: os.close(fd)


class LockedRegion:
    def __init__(self, capacity, runtime):
        require(sys.platform == "linux", "linux_required", "secret_region")
        runtime.require_armed()
        require(type(capacity) is int and 1 <= capacity <= 131072, "region_bound", "secret_region")
        import fcntl
        self.capacity, self.length, self.fd, self.mapping = capacity, 0, None, None
        self.libc = ctypes.CDLL(None, use_errno=True)
        try:
            self.fd = os.memfd_create("mail-device-secret", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            os.ftruncate(self.fd, capacity)
            self.mapping = mmap.mmap(self.fd, capacity, flags=mmap.MAP_SHARED,
                                     prot=mmap.PROT_READ | mmap.PROT_WRITE)
            address = ctypes.addressof(ctypes.c_char.from_buffer(self.mapping))
            require(self.libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(capacity)) == 0,
                    "mlock_failed", "secret_region")
            self.mapping.madvise(mmap.MADV_DONTDUMP)
            fcntl.fcntl(self.fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        except Exception:
            self.retire()
            raise

    def write(self, content):
        require(type(content) is bytes and len(content) <= self.capacity, "region_bound", "secret_write")
        self.mapping[:len(content)] = content
        self.length = len(content)
        os.lseek(self.fd, 0, os.SEEK_SET)

    def retire(self):
        if self.mapping is not None:
            address = ctypes.addressof(ctypes.c_char.from_buffer(self.mapping))
            ctypes.memset(ctypes.c_void_p(address), 0, self.capacity)
            self.libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(self.capacity))
            self.mapping.close()
            self.mapping = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.length = 0


class LinuxRegions:
    def __init__(self, runtime): self.runtime = runtime
    def allocate(self, capacity): return LockedRegion(capacity, self.runtime)


class PinnedOpenSSL:
    def __init__(self, executable_fd, expected_sha256, runtime):
        require(sys.platform == "linux", "linux_required", "openssl_port")
        runtime.require_armed()
        self.fd, self.runtime = os.dup(executable_fd), runtime
        metadata = os.fstat(self.fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                and metadata.st_mode & 0o022 == 0, "executable_metadata", "openssl_port")
        digest = hashlib.sha256()
        offset = 0
        while True:
            chunk = os.pread(self.fd, 65536, offset)
            if not chunk: break
            offset += len(chunk)
            require(offset <= 32 * 1024 * 1024, "executable_bound", "openssl_port")
            digest.update(chunk)
        require(digest.hexdigest() == expected_sha256, "executable_pin", "openssl_port")
        self.identity = os.fstat(self.fd)

    def run(self, command, regions):
        self.runtime.require_armed()
        require(os.fstat(self.fd) == self.identity, "executable_drift", command.phase)
        target = next((r for r in regions if r.fd == command.output_fd), None)
        require(target is not None, "output_descriptor", command.phase)
        # Logical argv[0] is fixed; executable is the held root-owned exact FD.
        os.lseek(target.fd, 0, os.SEEK_SET)
        descriptors = tuple(sorted(set(command.pass_fds + (self.fd,))))
        for fd in command.pass_fds: os.lseek(fd, 0, os.SEEK_SET)
        process = subprocess.Popen(command.argv, executable="/proc/self/fd/" + str(self.fd),
            stdin=subprocess.DEVNULL, stdout=target.fd, stderr=subprocess.PIPE,
            close_fds=True, pass_fds=descriptors, env={"LANG": "C", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"})
        # Drain continuously with a bounded retained metadata count, not raw text.
        counts = {"bytes": 0, "overflow": False, "codes": set(), "markers": set()}
        def drain():
            tail = b""
            while True:
                chunk = process.stderr.read(4096)
                if not chunk: break
                counts["bytes"] += len(chunk)
                window = tail + chunk
                counts["codes"].update(value.decode("ascii").lower() for value in re.findall(rb"error:([0-9A-Fa-f]{8,16}):", window))
                for marker, token in (("bad_decrypt",b"bad decrypt"), ("unsupported",b"unsupported"),
                        ("permission_denied",b"Permission denied"), ("no_start_line",b"no start line"),
                        ("no_space",b"No space left"), ("signature_failure",b"signature failure")):
                    if token in window: counts["markers"].add(marker)
                tail = window[-128:]
                if counts["bytes"] > 32768:
                    counts["overflow"] = True
                    process.kill()
                    break
        thread = threading.Thread(target=drain, daemon=True)
        thread.start()
        timed_out = False
        try:
            process.wait(timeout=45)
        except subprocess.TimeoutExpired:
            timed_out = True; process.kill(); process.wait()
        finally:
            thread.join(timeout=2)
            process.stderr.close()
        require(not thread.is_alive(), "stderr_drain_unverified", command.phase)
        if timed_out or counts["overflow"] or process.returncode != 0:
            raise AdapterError("native_timeout" if timed_out else "native_output_bound" if counts["overflow"] else "native_failed",
                               phase=command.phase, native_exit=process.returncode,
                               details={"stderr_bytes": counts["bytes"], "stderr_overflow": counts["overflow"],
                                        "openssl_error_codes": sorted(counts["codes"])[:16],
                                        "reason_markers": sorted(counts["markers"]), "raw_saved": False})
        target.length = os.lseek(target.fd, 0, os.SEEK_CUR)
        require(0 < target.length <= target.capacity, "native_output_size", command.phase)
        os.lseek(target.fd, 0, os.SEEK_SET)
