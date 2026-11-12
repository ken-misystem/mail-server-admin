"""Uninstalled exact-session DB reader. Never invoked by this turn's live read.

Private session reference arrives on the protected wire, not in HTTP input. Its
hash must match the MAC-verified context before this reader can query a row.
No PHP unserialize/session_decode/eval or object/reference deserialization.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from hashlib import sha256
import base64
import re
from transport_frozen import require, SessionRecord, SessionContext, session

SELECTED = frozenset({'user_id','username','storage_host','mail_auth_epoch',
                     'local_auth_gate_pending_v1','local_auth_emergency_recovery_v1'})


class ReferenceScope:
    def __init__(self): self.slot=ContextVar('private_session_reference',default=None)
    @contextmanager
    def bind(self, reference):
        require(self.slot.get() is None and type(reference)is str
                and re.fullmatch('[A-Za-z0-9,-]{16,256}',reference) is not None,
                'session_reference_shape', 'session_locator')
        token=self.slot.set(reference)
        try:yield
        finally:self.slot.reset(token)
    def current(self, binding):
        reference=self.slot.get()
        require(type(binding)is str and re.fullmatch('[0-9a-f]{64}',binding)is not None
                and type(reference)is str
                and sha256(b'mail-device-v1\0'+reference.encode('ascii')).hexdigest()==binding,
                'session_reference_binding', 'session_locator')
        return reference


class ScalarSessionParser:
    """Bounded PHP 'php' serializer parser, rejects objects/references globally.

    Unknown strings/arrays are skipped, not retained in the result. Lengths are
    BYTE lengths, not Unicode character counts. All errors are fixed reason codes.
    """
    def __init__(self, raw):
        require(type(raw)is bytes and 0<len(raw)<=262144,'session_blob_bound','session_parse')
        self.raw,self.pos,self.nodes=raw,0,0
    def take(self,n):
        require(type(n)is int and 0<=n<=131072 and self.pos+n<=len(self.raw),'session_blob_truncated','session_parse')
        value=self.raw[self.pos:self.pos+n];self.pos+=n;return value
    def expect(self,value):require(self.take(len(value))==value,'session_blob_framing','session_parse')
    def number(self,end):
        stop=self.raw.find(end,self.pos,self.pos+22)
        require(stop>=self.pos,'session_number_framing','session_parse')
        raw=self.raw[self.pos:stop];self.pos=stop+len(end)
        require(re.fullmatch(rb'-?(0|[1-9][0-9]{0,19})',raw)is not None,'session_number_shape','session_parse')
        return int(raw)
    def value(self,keep,depth=0):
        self.nodes+=1
        require(depth<=16 and self.nodes<=4096,'session_structure_bound','session_parse')
        kind=self.take(1)
        if kind==b'N':self.expect(b';');return None
        require(kind in (b'b',b'i',b's',b'a'), 'session_unsupported_serialized_type','session_parse')
        self.expect(b':')
        if kind in (b'b',b'i'):
            value=self.number(b';')
            if kind==b'b':require(value in (0,1),'session_bool_shape','session_parse');value=bool(value)
            return value if keep else None
        size=self.number(b':')
        require(size>=0,'session_negative_size','session_parse')
        if kind==b's':
            self.expect(b'"');raw=self.take(size);self.expect(b'";')
            return raw if keep else None
        require(size<=2048,'session_array_bound','session_parse');self.expect(b'{')
        # Selected scalar fields must not be arrays. Gate fields use presence only.
        require(not keep,'session_selected_scalar_required','session_parse')
        for _ in range(size):self.value(False,depth+1);self.value(False,depth+1)
        self.expect(b'}');return None
    def parse(self):
        result={};seen=set()
        while self.pos<len(self.raw):
            stop=self.raw.find(b'|',self.pos,self.pos+129)
            require(stop>self.pos,'session_variable_framing','session_parse')
            key=self.raw[self.pos:stop]
            # Session keys are byte strings, not PHP variable identifiers.
            # Unknown auxiliary names never become selected identity fields.
            require(key not in seen,'session_variable_duplicate','session_parse')
            require(not any(byte<32 or byte==127 for byte in key),
                    'session_variable_control_byte','session_parse')
            seen.add(key);require(len(seen)<=256,'session_variable_bound','session_parse')
            name=key.decode('ascii')if key in {field.encode('ascii')for field in SELECTED}else None;self.pos=stop+1
            keep=name in SELECTED and name not in {'local_auth_gate_pending_v1','local_auth_emergency_recovery_v1'}
            value=self.value(keep)
            if name in SELECTED:result[name]=value
        return result


class DbSessionRecords:
    QUERIES={
        'changed_v1':'SELECT vars,UNIX_TIMESTAMP(changed) FROM roundcube.session WHERE sess_id=%s LIMIT 2',
        'expires_at_v1':'SELECT vars,UNIX_TIMESTAMP(expires_at) FROM roundcube.session WHERE sess_id=%s LIMIT 2'}
    def __init__(self,runtime,connector,references,lifetime_seconds,clock,readiness,profile):
        require(type(lifetime_seconds)is int and 60<=lifetime_seconds<=86400,'session_lifetime_bound','session_store')
        require(type(profile)is str and profile in self.QUERIES,'session_schema_profile','session_store')
        self.runtime,self.connector,self.references=runtime,connector,references
        self.lifetime,self.clock,self.readiness,self.profile=lifetime_seconds,clock,readiness,profile
    def current(self,binding):
        self.runtime.require_armed()
        self.readiness.require_current('roundcube_db_session_schema_serializer_and_least_privilege')
        reference=self.references.current(binding)  # BEFORE credential/DB access.
        with session(self.connector,readonly=True) as (_,cursor):
            # This connection reads only Roundcube sessions. Its DATETIME writer
            # uses the database default zone; the shared DB helper forces UTC.
            # Restore the writer's default on this dedicated connection only.
            if self.profile == 'changed_v1':
                cursor.execute("SET SESSION time_zone = DEFAULT")
            cursor.execute(self.QUERIES[self.profile],(reference,));rows=cursor.fetchmany(2)
            require(type(rows) in (tuple,list) and len(rows)==1 and type(rows[0])is tuple and len(rows[0])==2,
                    'session_row_missing_or_ambiguous','session_store')
            raw,changed=rows[0]
        if type(raw)is str:raw=raw.encode('utf-8','strict')
        require(type(raw)is bytes and 0<len(raw)<=349528,'session_encoded_bound','session_store')
        decoded=base64.b64decode(raw,validate=True)
        require(base64.b64encode(decoded)==raw,'session_base64_noncanonical','session_store')
        values=ScalarSessionParser(decoded).parse();raw=decoded=reference=None
        user,epoch=values.get('user_id'),values.get('mail_auth_epoch')
        if type(user)is bytes and re.fullmatch(rb'[1-9][0-9]{0,9}',user):user=int(user)
        require(type(user)is int and 0<user<=4294967295 and type(epoch)is int and 0<=epoch<2**64,
                'session_owner_or_epoch_type','session_store')
        require(type(changed)is int and changed>=0,'session_changed_timestamp_type','session_store')
        require(self.profile!='changed_v1' or changed<=self.clock(),'session_changed_in_future','session_store')
        require(type(values.get('username'))is bytes and type(values.get('storage_host'))is bytes,
                'session_identity_type','session_store')
        context=SessionContext(user,values['username'].decode('ascii','strict'),
                               values['storage_host'].decode('ascii','strict'),binding)
        expires=changed+self.lifetime if self.profile=='changed_v1' else changed
        return SessionRecord(context,epoch,expires,self.clock(),True,
            'local_auth_gate_pending_v1' in values,'local_auth_emergency_recovery_v1' in values)

