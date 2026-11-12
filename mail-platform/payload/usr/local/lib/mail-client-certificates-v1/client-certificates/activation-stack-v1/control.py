"""Exact-generation actuation ports, not success stubs or installed services."""
from hashlib import sha256
import json
import uuid

COMPONENTS=frozenset({'imaps','pop3s','submission','resumption','existing_sessions','crl','material_retired'})


def need(ok,reason):
    if ok is not True:raise ValueError(reason)


def request(device,generation,epoch,identity_version):
    need(type(device)is str and str(uuid.UUID(device))==device and uuid.UUID(device).version==4,
         'control_device_identity')
    need(all(type(v)is int for v in (generation,epoch,identity_version))
         and generation>0 and epoch>=0 and identity_version>0,'control_generation_scope')
    payload={'device_id':device,'generation':generation,'owner_epoch':epoch,
             'owner_identity_version':identity_version}
    pin=sha256(json.dumps(payload,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return payload,pin


def collect(device,generation,epoch,identity_version,publishers):
    """Each publisher must be a peer-checked concrete transport, never browser data.

    Missing, partial and failed acknowledgements stay pending. A false boolean
    or a different generation cannot complete revocation. No key or mail data.
    """
    payload,pin=request(device,generation,epoch,identity_version)
    need(type(publishers)is dict and set(publishers)==COMPONENTS,'control_component_inventory')
    acknowledged=set();failures=[]
    for name in sorted(COMPONENTS):
        try:
            response=publishers[name](dict(payload))
            need(type(response)is dict and set(response)=={'component','binding_sha256','applied'}
                 and response['component']==name and response['binding_sha256']==pin
                 and response['applied'] is True,'control_ack_binding')
            acknowledged.add(name)
        except Exception as error:
            failures.append({'component':name,'class':type(error).__name__,
                'reason':'control_ack_binding' if type(error)is ValueError and error.args==('control_ack_binding',)
                    else 'publisher_failed','errno':getattr(error,'errno',None),'raw_message_saved':False})
    return {'generation':generation,'acknowledged':sorted(acknowledged),
        'pending':sorted(COMPONENTS-acknowledged),'failures':failures,
        'complete':frozenset(acknowledged)==COMPONENTS}


def serve_policy(channel,runtime,readiness,peer_guard,decide,sessions,registry,audit,clock):
    """Send response BEFORE close. Old Entrance.policy returns after closing.

    Native policy is not JSON. Unauthenticated peers receive no application data.
    Existing restriction ordering and backend identity remain separate gates.
    """
    authenticated=False;phase='policy_peer'
    try:
        runtime.require_armed();readiness.require_current('smtp_policy')
        peer_guard(channel);authenticated=True;deadline=clock()+5;raw=bytearray()
        phase='policy_read'
        while not raw.endswith(b'\n\n'):
            need(len(raw)<32768 and clock()<deadline,'policy_frame_bound')
            channel.settimeout(deadline-clock());part=channel.recv(1)
            need(type(part)is bytes and len(part)==1,'policy_frame_eof');raw.extend(part)
        response=decide(bytes(raw),sessions,registry,peer_verified=True)
        need(type(response)is bytes and len(response)<=512 and response.startswith(b'action=')
             and response.endswith(b'\n\n'),'policy_response_scope')
        phase='policy_send';channel.sendall(response)
        return True
    except Exception as error:
        try:audit.failure(error,phase)
        finally:
            if authenticated:
                try:channel.sendall(b'action=451 4.3.5 Device authorization unavailable\n\n')
                except OSError:pass
        return False
    finally:channel.close()


def relay_with_revocation(delegate,sessions,client,backend,identity,registry,clock):
    """A verified explicit drain closes both FDs. Other relay errors still fail."""
    try:return delegate(client,backend,identity,registry,clock)
    except (OSError,ValueError):
        with sessions.lock:
            generation=sessions.denied.get(identity.device_id,0)
            if type(generation)is int and generation>0 and client.fileno()==backend.fileno()==-1:
                return
        raise
