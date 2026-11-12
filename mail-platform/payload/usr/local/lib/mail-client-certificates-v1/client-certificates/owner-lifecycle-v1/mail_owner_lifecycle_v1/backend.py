"""Explicit adapters to existing owner scope/verifier; no boot or secret loading."""
import base64
from hashlib import sha256
import re
from .stepup import Authority as LeaseAuthority, Binding, VerifiedCredential, need


class Authority(LeaseAuthority):
    def current(self, expected, now):
        lease = super().current(expected, now)
        # The credential-status RPC may cross the deadline. Verify the clock
        # after that RPC as well; a slow status read cannot extend the window.
        observed = self.now()
        if lease is not None and not lease.issued <= observed < lease.expires:
            self.invalidate(expected); return None
        return lease


def binding(owner):
    result = Binding(owner.owner_id, owner.roundcube_id, owner.epoch, owner.identity_version, owner.session_hash)
    result.validate(); need(owner.active is True, 'owner_inactive'); return result


def credential(value):
    need(type(value) is str and re.fullmatch('[A-Za-z0-9_-]{1,1364}', value) is not None, 'credential_encoding')
    raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
    need(0 < len(raw) <= 1023 and base64.urlsafe_b64encode(raw).decode().rstrip('=') == value, 'credential_canonical')
    return raw


class TrustedVerifier:
    def __init__(self, wire, current_owner): self.wire, self.owner = wire, current_owner
    def check(self, expected): need(binding(self.owner()) == expected, 'current_owner_changed')
    def begin(self, expected):
        self.check(expected); value = self.wire.call('begin', {'uid':expected.roundcube_id,'binding':expected.session_hash})
        need(type(value) is dict and set(value) == {'ceremony_id','publicKey'}, 'verifier_begin_contract')
        self.check(expected); return value['ceremony_id'], value['publicKey']
    def finish(self, expected, ceremony, assertion):
        self.check(expected)
        value = self.wire.call('finish_lease', {'uid':expected.roundcube_id,'binding':expected.session_hash,'ceremony':ceremony,'response':assertion})
        need(type(value) is dict and set(value) == {'verified','credential_id'} and value['verified'] is True, 'verifier_uv_receipt')
        self.check(expected); return VerifiedCredential(credential(value['credential_id']))
    def enabled(self, expected, identifier):
        self.check(expected)
        value = self.wire.call('credential_enabled', {'uid':expected.roundcube_id,'binding':expected.session_hash,
                                                    'credential_id':base64.urlsafe_b64encode(identifier).decode().rstrip('=')})
        need(type(value) is dict and set(value) == {'enabled'} and type(value['enabled']) is bool, 'credential_status_receipt')
        self.check(expected); return value['enabled']


def verifier_handler(service, previous):
    def handle(operation, data):
        if operation not in ('finish_lease', 'credential_enabled'): return previous(operation,data)
        fields = {'uid','binding','ceremony','response'} if operation=='finish_lease' else {'uid','binding','credential_id'}
        need(type(data) is dict and set(data) == fields and type(data['uid']) is int and data['uid'] > 0
             and type(data['binding']) is str and re.fullmatch('[a-f0-9]{64}',data['binding']) is not None, 'verification_rpc_scope')
        service.runtime.require_armed()
        if operation == 'finish_lease':
            # Existing implementation validates RP/origin/challenge/owner/UP/UV/signature
            # and updates its credential counter. No new cryptographic verifier.
            service.finish(data['uid'],data['binding'],data['ceremony'],data['response'])
            need(type(data['response']) is dict, 'verified_assertion_object')
            # Existing verifier selects and verifies rawId, not the display id.
            identifier = data['response']['rawId']; credential(identifier)
            return {'verified':True,'credential_id':identifier}
        identifier = credential(data['credential_id']); connection = service.connector(); cursor = None
        try:
            cursor = connection.cursor()
            cursor.execute('SELECT enabled FROM roundcube.auth_webauthn_credentials WHERE user_id=%s AND credential_id=%s LIMIT 2',(data['uid'],identifier))
            rows = cursor.fetchmany(2)
            need(type(rows) in (list, tuple) and len(rows) <= 1, 'credential_status_unique')
            need(not rows or type(rows[0]) is tuple and len(rows[0]) == 1 and type(rows[0][0]) is int
                 and rows[0][0] in (0, 1), 'credential_status_type')
            return {'enabled': bool(rows and rows[0][0] == 1)}
        finally:
            try:
                if cursor is not None: cursor.close()
            finally: connection.close()
    return handle


def wrap_actions(original_actions, authority, action_module):
    """Preserve old per-owner/purpose/target one-use action; replace UV repetition only."""
    def purpose(name): return {'issue':'certificate_issue','revoke':'certificate_revoke'}[name]
    class Proof:
        def consume(self, owner, name, target, action_id, assertion, now):
            action = original_actions.store.pop(owner.owner_id, action_id)
            action_module.ActionProof.matches(action, owner, name, target, now)
            current = binding(owner); digest = sha256(target.encode()).hexdigest()
            if action.ceremony_id.startswith('shared-uv:'):
                authority.finish(current, action.ceremony_id[len('shared-uv:'):], assertion)
                authorization = authority.authorize(current,purpose(name),digest)['authorization_id']
            else:
                need(action.ceremony_id.startswith('shared-lease:') and assertion is None,'leased_action_format')
                authorization = action.ceremony_id[len('shared-lease:'):]
            authority.consume(current,purpose(name),digest,authorization)
    class Actions(type(original_actions)):
        def begin(self, owner, name, target, request_id, device_id, label):
            import uuid
            current = binding(owner); status = authority.status(current); now = self.service.clock()
            if status['authentication_required']:
                start = authority.begin(current)
                # A concurrent verified request may have created a lease in between.
                if not start['authentication_required']: return self.begin(owner,name,target,request_id,device_id,label)
                ceremony = 'shared-uv:' + start['action_id']; options = start['publicKey']; expires = now+300
            else:
                grant = authority.authorize(current,purpose(name),sha256(target.encode()).hexdigest())
                ceremony = 'shared-lease:' + grant['authorization_id']; options = {}; expires = now+min(120,grant['remaining_seconds'])
            action = action_module.BoundAction(str(uuid.uuid4()),owner,name,target,request_id,device_id,label,ceremony,expires)
            self.store.create(action)
            return {'action_id':action.id,'publicKey':options,'authentication_required':status['authentication_required'],
                    'remaining_seconds':status['remaining_seconds']}
    updated = Actions(original_actions.service,original_actions.store,original_actions.webauthn)
    updated.service.proof = Proof(); return updated


class SharedDispatcher:
    FIELDS = {'verification_status':set(),'verification_options':set(),
              'verification_finish':{'action_id','assertion'},'verification_authorize':{'purpose','target'},
              'verification_consume':{'purpose','target','authorization_id'},'verification_invalidate':set()}
    def __init__(self, previous, authority): self.previous,self.authority=previous,authority
    def dispatch(self, operation, context, data):
        if operation not in self.FIELDS: return self.previous.dispatch(operation,context,data)
        need(type(data) is dict and set(data) == self.FIELDS[operation], 'shared_verification_fields')
        with self.previous.scope.enter(context) as session:
            owner = self.previous.service.owner(session); self.previous.scope.bind_owner(owner); current = binding(owner)
            if operation == 'verification_status': return self.authority.status(current)
            if operation == 'verification_options': return self.authority.begin(current)
            if operation == 'verification_finish': return self.authority.finish(current,data['action_id'],data['assertion'])
            if operation == 'verification_authorize': return self.authority.authorize(current,data['purpose'],data['target'])
            if operation == 'verification_consume': return {'authorized':self.authority.consume(current,data['purpose'],data['target'],data['authorization_id'])}
            self.authority.invalidate(current); return {'invalidated':True}
    def download(self,*args): return self.previous.download(*args)
