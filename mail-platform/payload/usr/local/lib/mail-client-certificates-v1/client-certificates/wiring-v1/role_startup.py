"""Explicit role FD/request/broker assembly. No credentials read on import/build.

Borrowed FDs stay with the trusted bootstrap; no UID/account/user/key generation.
No FPM/daemon/service start. Dedicated Linux protection is required by runtime.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import os
import stat
from frozen_runtime import (require, Owner, Receipt, domain, actions, RoleConnector, Endpoint,
    SessionContext, OwnerIdentity, IdentitySnapshot, BoundRepository, LiveRegistry)
from authority import BrokerAuthority
from broker import IssuerBroker

ACTORS = {'orchestrator':frozenset({'identity_reader','orchestrator','gateway_reader'}),
          'broker':frozenset({'issuer_journal'})}


class RoleFDs:
    def __init__(self, actor, descriptors, runtime, uid):
        require(type(actor) is str and actor in ACTORS and type(descriptors) is dict
                and set(descriptors) == ACTORS[actor]
                and all(type(fd) is int and fd > 2 for fd in descriptors.values())
                and len(set(descriptors.values())) == len(descriptors)
                and type(uid) is int and uid > 0, 'role_fd_inventory', 'role_startup')
        self.actor, self.fds, self.runtime, self.uid = actor, dict(descriptors), runtime, uid

    def verify(self):
        self.runtime.require_armed()
        require(os.geteuid() == self.uid, 'role_fd_uid', 'role_startup')
        identities = set()
        for fd in self.fds.values():
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid and info.st_nlink == 1
                    and info.st_mode & 0o077 == 0 and 0 < info.st_size <= 8192
                    and os.get_inheritable(fd) is False, 'role_fd_metadata', 'role_startup')
            key = info.st_dev, info.st_ino
            require(key not in identities, 'role_fd_alias', 'role_startup')
            identities.add(key)

    def connectors(self, principals, socket_path):
        self.verify()
        require(type(principals) is dict and set(principals) == set(self.fds)
                and len(set(principals.values())) == len(principals), 'role_principal_inventory', 'role_startup')
        return {role:RoleConnector(fd,self.runtime,Endpoint(socket_path,principals[role],'mail_management'))
                for role,fd in self.fds.items()}


class RequestScope:
    def __init__(self, live_session):
        self.live = live_session
        self.frame = ContextVar('certificate_request_frame',default=None)

    @contextmanager
    def enter(self, context):
        require(type(context) is SessionContext and self.frame.get() is None,
                'request_context_or_reentry', 'request_scope')
        value = {'context':context,'key':object(),'owner':None}
        token = self.frame.set(value)
        try: yield value['key']
        finally: self.frame.reset(token)

    def authenticated(self, key):
        frame = self.frame.get()
        require(frame is not None and key is frame['key'], 'request_session_reference', 'request_scope')
        current = self.live.current(frame['context'])
        require(type(current) is SessionContext and current == frame['context'],
                'request_session_changed', 'request_scope')
        return current

    def bind_owner(self, owner):
        frame = self.frame.get()
        require(frame is not None and type(owner) is Owner and frame['owner'] is None,
                'request_owner_binding', 'request_scope')
        frame['owner'] = owner

    def owner(self):
        frame = self.frame.get()
        require(frame is not None and type(frame['owner']) is Owner,
                'request_owner_required', 'request_scope')
        return frame['owner']


class BrokerProxy:
    def __init__(self, channel, runtime): self.channel, self.runtime = channel, runtime
    def prepare(self, device, password, now):
        self.runtime.require_armed(); self.channel.require_peer()
        receipt = self.channel.prepare(device, password, now)
        require(type(receipt) is Receipt and receipt.device_id == device.id,
                'broker_receipt_binding', 'broker_proxy')
        return receipt
    def stream(self, device_id, writer):
        self.runtime.require_armed(); self.channel.require_peer()
        return self.channel.stream(device_id,writer)
    def retire(self, device_id):
        self.runtime.require_armed(); self.channel.require_peer()
        return self.channel.retire(device_id)


class Dispatcher:
    def __init__(self, service, ceremonies, scope): self.service, self.ceremonies, self.scope = service, ceremonies, scope
    def dispatch(self, operation, context, data):
        require(type(data) is dict, 'dispatch_input', 'dispatch')
        fields = {'list':{'cursor'},'issue_options':{'label','request_id'},
                  'issue_finish':{'action_id','assertion','p12_password'},
                  'revoke_options':{'device_id','request_id'},'revoke_finish':{'action_id','assertion'}}
        require(type(operation) is str and operation in fields and set(data) <= fields[operation]
                and (operation == 'list' or set(data) == fields[operation]), 'dispatch_scope', 'dispatch')
        with self.scope.enter(context) as session:
            self.scope.bind_owner(self.service.owner(session))
            if operation == 'list': return self.service.listing(session,data.get('cursor'))
            if operation == 'issue_options': return self.ceremonies.issue_options(session,data['label'],data['request_id'])
            if operation == 'issue_finish': return self.ceremonies.issue_finish(session,data['action_id'],data['assertion'],data['p12_password'])
            if operation == 'revoke_options': return self.ceremonies.revoke_options(session,data['device_id'],data['request_id'])
            return self.ceremonies.revoke_finish(session,data['action_id'],data['assertion'])

    def download(self, context, data, writer):
        require(type(data) is dict and set(data) == {'device_id','download_handle'},
                'download_dispatch_scope', 'dispatch')
        with self.scope.enter(context) as session:
            self.scope.bind_owner(self.service.owner(session))
            return self.service.download(session,data['device_id'],data['download_handle'],writer)


def orchestrator(fd_set, principals, socket_path, live_session, broker_channel,
                 enforcement, audit, action_store, webauthn, clock):
    require(type(fd_set) is RoleFDs and fd_set.actor == 'orchestrator', 'startup_actor', 'assembly')
    connectors = fd_set.connectors(principals,socket_path)
    scope = RequestScope(live_session)
    identity = OwnerIdentity(scope,IdentitySnapshot(connectors['identity_reader']))
    repository = BoundRepository(connectors['orchestrator'],scope.owner)
    registry = LiveRegistry(connectors['gateway_reader'])
    proof = actions.ActionProof(action_store,webauthn)
    service = domain.Service(identity,proof,repository,BrokerProxy(broker_channel,fd_set.runtime),enforcement,audit,clock)
    return {'dispatcher':Dispatcher(service,actions.Actions(service,action_store,webauthn),scope),
            'registry':registry,'scope':scope,'connectors':connectors}


def broker(fd_set, principals, socket_path, owner_provider, regions, runner, inspector, issuer, clock, audit):
    require(type(fd_set) is RoleFDs and fd_set.actor == 'broker', 'startup_actor', 'assembly')
    connector = fd_set.connectors(principals,socket_path)['issuer_journal']
    registry = LiveRegistry(connector)
    repository = BoundRepository(connector,owner_provider)
    return IssuerBroker(BrokerAuthority(repository,registry),regions,runner,inspector,issuer,clock,audit)


def authenticated_application(fd_set, principals, socket_path, live_session, broker_channel,
                              enforcement, audit, action_store, webauthn, clock, auth_key_fd, monotonic):
    """FD->key authority->fresh request identity->core actions->broker proxy.

    This constructor never reads credentials/keys or starts a socket listener.
    The authenticated connection adapter must supply KERNEL peer values only.
    """
    from attestation import SessionAuthority, KeyFD, AuthenticatedDispatcher
    require(type(auth_key_fd) is int and auth_key_fd > 2 and auth_key_fd not in fd_set.fds.values(),
            'auth_role_fd_collision', 'assembly')
    components = orchestrator(fd_set,principals,socket_path,live_session,broker_channel,
                              enforcement,audit,action_store,webauthn,clock)
    auth_info = os.fstat(auth_key_fd)
    require(all((os.fstat(fd).st_dev,os.fstat(fd).st_ino) != (auth_info.st_dev,auth_info.st_ino)
                for fd in fd_set.fds.values()), 'auth_role_inode_collision', 'assembly')
    authority = SessionAuthority(fd_set.runtime,KeyFD(auth_key_fd,fd_set.runtime),live_session,monotonic)
    components['session_authority'] = authority
    components['authenticated_dispatcher'] = AuthenticatedDispatcher(authority,components['dispatcher'])
    return components
