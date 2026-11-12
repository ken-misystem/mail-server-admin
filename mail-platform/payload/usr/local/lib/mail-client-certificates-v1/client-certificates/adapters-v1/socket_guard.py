"""Anchored no-follow private socket paths from an immutable operator manifest."""
from dataclasses import dataclass
import os
import stat
from core import require


@dataclass
class Held:
    descriptors: list
    components: list
    leaf: str
    metadata: object
    rule: dict


class SocketGuard:
    def __init__(self, manifest): self.manifest = manifest

    def open_socket_parent(self, path):
        require(path in self.manifest and path.startswith("/") and "//" not in path,
                "socket_not_in_manifest", "socket_guard")
        pieces = path.split("/")[1:]
        require(len(pieces) <= 32 and all(p and p not in {".", ".."} for p in pieces),
                "socket_path_shape", "socket_guard")
        rule = self.manifest[path]
        descriptors = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
        try:
            for name in pieces[:-1]:
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1])
                descriptors.append(fd)
                metadata = os.fstat(fd)
                require(metadata.st_uid in rule["parent_uids"] and metadata.st_mode & 0o022 == 0,
                        "socket_parent_permissions", "socket_guard")
            value = os.stat(pieces[-1], dir_fd=descriptors[-1], follow_symlinks=False)
            require(stat.S_ISSOCK(value.st_mode) and value.st_uid == rule["uid"] and value.st_gid == rule["gid"]
                    and stat.S_IMODE(value.st_mode) == rule["mode"] and value.st_mode & 0o007 == 0,
                    "socket_leaf_permissions", "socket_guard")
            return Held(descriptors, pieces[:-1], pieces[-1], value, rule)
        except Exception:
            for fd in reversed(descriptors): os.close(fd)
            raise

    def verify_leaf(self, held):
        for index, name in enumerate(held.components):
            named = os.stat(name, dir_fd=held.descriptors[index], follow_symlinks=False)
            opened = os.fstat(held.descriptors[index+1])
            require((named.st_dev,named.st_ino)==(opened.st_dev,opened.st_ino)
                    and stat.S_ISDIR(named.st_mode) and named.st_mode & 0o022 == 0,
                    "socket_parent_drift", "socket_guard")
        require(os.stat(held.leaf, dir_fd=held.descriptors[-1], follow_symlinks=False) == held.metadata,
                "socket_leaf_drift", "socket_guard")

    def anchored_socket_name(self, held):
        self.verify_leaf(held)
        return "/proc/self/fd/" + str(held.descriptors[-1]) + "/" + held.leaf

    def close(self, held):
        for fd in reversed(held.descriptors): os.close(fd)
