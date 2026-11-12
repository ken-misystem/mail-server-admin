"""Concrete LoadCredential descriptor inventory; no environment credentials."""
import os
import stat
from pathlib import PurePosixPath
from peer import need
ROLES={'owner':('identity_reader','orchestrator','gateway_reader','session_reader'),
    'lifecycle':('lifecycle_provisioner',),'verifier':('webauthn_verifier',),
    'issuer':('issuer_journal','issuer_certificate','issuer_key','issuer_password')}
class Credentials:
    def __init__(self,actor,directory,runtime):
        need(actor in ROLES and type(directory)is str and directory.startswith('/run/credentials/')
            and str(PurePosixPath(directory))==directory and '..'not in directory.split('/'),'credential_directory')
        self.actor,self.directory,self.runtime,self.fds=actor,directory,runtime,{}
    def open(self):
        self.runtime.require_armed();need(not self.fds,'credential_inventory_already_open')
        parent=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            entry=os.fstat(parent);need(entry.st_uid in(0,os.geteuid())and entry.st_mode&0o022==0,'credential_parent_mode')
            for role in ROLES[self.actor]:
                fd=os.open(role,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent);self.fds[role]=fd
                entry=os.fstat(fd);need(stat.S_ISREG(entry.st_mode)and entry.st_uid==os.geteuid()and entry.st_nlink==1
                    and entry.st_mode&0o077==0 and 0<entry.st_size<=65536,'credential_file_metadata')
            identities=[(os.fstat(fd).st_dev,os.fstat(fd).st_ino)for fd in self.fds.values()];need(len(set(identities))==len(identities),'credential_inode_alias')
            return dict(self.fds)
        except BaseException:self.close();raise
        finally:os.close(parent)
    def close(self):
        for fd in self.fds.values():os.close(fd)
        self.fds.clear()
