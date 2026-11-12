"""Trusted local SMTP peer -> fresh identity check -> editable limits -> FULL ledger."""
import re
import secrets
import socket
import struct
import time
from policy import CONTEXT, UNAVAILABLE, need, parse_frame, principal
from owner_control import gate, STOPPED
from owner_stop_file import load_stop
from profile_runtime import Profiles, evaluate as evaluate_profile


class Service:
    def __init__(self, reader, writer, clock=time.time):
        self.reader=reader
        self.writer=writer
        self.clock=clock
        self.profiles=Profiles(reader.profiles)
        self.load_stop=load_stop

    def evaluate(self, raw, nonce, *, peer_verified=False):
        try:
            need(peer_verified is True,'untrusted_peer')
            fields=parse_frame(raw)
            need(fields.get('request')=='smtpd_access_policy' and fields.get('protocol_state')=='DATA'
                 and fields.get('policy_context')==CONTEXT,'policy_scope')
            username=fields.get('sasl_username','')
            if re.fullmatch(r'legacy-smtp-[1-9][0-9]{0,18}',username):
                self.reader.legacy(username)
                mailbox_id=None
            else:
                mailbox_id=self.reader.mailbox(username)
            owner=principal(username,lambda ignored:mailbox_id)
            now=int(self.clock())
            if gate(self.load_stop(owner),now):return STOPPED
            return evaluate_profile(raw,nonce,lambda ignored:mailbox_id,self.writer,now,self.profiles,
                peer_verified=True)
        except Exception:
            return UNAVAILABLE

    def serve(self, channel, expected_uid):
        try:
            need(type(expected_uid) is int and expected_uid>=0 and channel.family==socket.AF_UNIX
                 and hasattr(socket,'SO_PEERCRED'),'unix_peer_required')
            pid,uid,gid=struct.unpack('3i',channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
            need(pid>0 and uid==expected_uid,'unix_peer_uid')
            nonce=secrets.token_bytes(32)
            deadline=time.monotonic()+120
            for _ in range(100):
                frame=bytearray()
                while not frame.endswith(b'\n\n'):
                    remaining=min(5,deadline-time.monotonic())
                    need(remaining>0 and len(frame)<32768,'request_bound')
                    channel.settimeout(remaining)
                    piece=channel.recv(1)
                    if not piece:
                        return
                    frame.extend(piece)
                channel.sendall(self.evaluate(bytes(frame),nonce,peer_verified=True))
        except Exception:
            try:
                channel.settimeout(1)
                channel.sendall(UNAVAILABLE)
            except OSError:
                pass
        finally:
            channel.close()
