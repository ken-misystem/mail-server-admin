"""Separate session reader FD inventory; no credentials read or DB connect on construction."""
import os
import stat

ROLES = frozenset({'identity_reader','orchestrator','gateway_reader','session_reader'})


def need(ok, reason):
    if ok is not True:
        raise ValueError(reason)


class SessionReaderFD:
    def __init__(self, descriptors, auth_fd, uid, runtime, readiness):
        need(type(descriptors) is dict and set(descriptors) == ROLES
             and all(type(fd) is int and fd > 2 for fd in descriptors.values())
             and type(auth_fd) is int and auth_fd > 2
             and len(set([*descriptors.values(),auth_fd])) == 5
             and type(uid) is int and uid > 0, 'session_role_inventory')
        self.descriptors,self.auth_fd,self.uid=dict(descriptors),auth_fd,uid
        self.runtime,self.readiness=runtime,readiness

    def verify(self):
        self.runtime.require_armed()
        self.readiness.require_current('live_session_table_binding_and_effective_minimal_grants')
        need(os.getuid() == os.geteuid() == self.uid, 'session_role_uid')
        inodes=set()
        for fd in [*self.descriptors.values(),self.auth_fd]:
            info=os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid
                 and info.st_nlink == 1 and info.st_mode & 0o077 == 0
                 and 0 < info.st_size <= 8192 and os.get_inheritable(fd) is False,
                 'session_role_fd_metadata')
            key=info.st_dev,info.st_ino
            need(key not in inodes,'session_role_inode_alias');inodes.add(key)

    def session_connector(self, principal, socket_path, connector_api):
        self.verify()
        # connector_api is the pinned isolated session-only module, not old Endpoint.
        return connector_api.RoleConnector(self.descriptors['session_reader'],self.runtime,
            connector_api.Endpoint(socket_path,principal,'roundcube'))

    def original_roles(self, original_role_class):
        self.verify()
        return original_role_class('orchestrator',
            {key:value for key,value in self.descriptors.items() if key != 'session_reader'},
            self.runtime,self.uid)
