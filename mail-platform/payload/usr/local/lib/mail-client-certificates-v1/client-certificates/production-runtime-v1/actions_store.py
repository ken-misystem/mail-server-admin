"""Bounded single-process action storage; restart loses pending actions, never allows.

    No private keys, passwords, assertions, session variables or SQL are stored.
    The daemon uses threads; sharing this store across independent workers is
    deliberately unsupported. Signing reservations remain in the existing DB.
"""
import threading
import uuid


class ActionStore:
    def __init__(self,clock,action_type):
        self.clock,self.action_type=clock,action_type;self.rows={};self.lock=threading.RLock()

    def expire(self):
        now=self.clock();self.rows={key:value for key,value in self.rows.items()if value.expires>now}

    def create(self,action):
        if type(action)is not self.action_type or str(uuid.UUID(action.id))!=action.id:raise ValueError('action_shape')
        with self.lock:
            self.expire();key=(action.owner.owner_id,action.id)
            if key in self.rows or len(self.rows)>=512 or sum(k[0]==key[0]for k in self.rows)>=2:raise ValueError('action_pending_limit')
            if not self.clock()<action.expires<=self.clock()+300:raise ValueError('action_expiry')
            self.rows[key]=action

    def peek(self,owner_id,action_id):
        with self.lock:self.expire();return self.rows.get((owner_id,action_id))

    def pop(self,owner_id,action_id):
        with self.lock:self.expire();return self.rows.pop((owner_id,action_id),None)
