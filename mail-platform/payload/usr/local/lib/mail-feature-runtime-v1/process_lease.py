"""Linux process-level writer lease in the dedicated private database directory."""
import os
import stat


class ProcessLease:
    def __init__(self, path):
        import fcntl
        self.fd = None
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            parent = os.fstat(parent_fd)
            if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) != 0o700:
                raise ValueError('lease_parent')
            descriptor = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent_fd)
        except BaseException:
            os.close(parent_fd)
            raise
        try:
            facts = os.fstat(descriptor)
            if not stat.S_ISREG(facts.st_mode) or facts.st_uid != os.geteuid() or facts.st_nlink != 1 or stat.S_IMODE(facts.st_mode) != 0o600:
                raise ValueError('lease_file')
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            named = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (facts.st_dev, facts.st_ino) != (named.st_dev, named.st_ino):
                raise ValueError('lease_replaced')
            self.fd = descriptor
        except BaseException:
            os.close(descriptor)
            raise
        finally:
            os.close(parent_fd)

    def close(self):
        if self.fd is not None:
            descriptor, self.fd = self.fd, None
            os.close(descriptor)
