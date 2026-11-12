"""Bounded P12 pull protocol; no issuance, listener, or input secret logging."""
import json
import os
import struct
from transport_frozen import require, receive, unique


class RemoteRegion:
    """Internal proxy only. Never deserialize a generic object into this class."""
    def __init__(self,length,reader):self.length,self.reader=length,reader


def material_read(region,offset,count):
    if type(region)is RemoteRegion:return region.reader(offset,count)
    return os.pread(region.fd,count,offset)


def send(channel,payload,clock,deadline):
    require(type(payload)is bytes and 0<len(payload)<=65536 and clock()<deadline,
            'transfer_send_bound','transfer')
    channel.settimeout(max(.001,deadline-clock()))
    channel.sendall(struct.pack('!I',len(payload))+payload)


def control(channel,value,clock,deadline):
    send(channel,json.dumps(value,separators=(',',':'),allow_nan=False).encode(),clock,deadline)


class PullDestination:
    def __init__(self,channel,runtime,current,retire,clock,read_at=None):
        self.channel,self.runtime,self.current,self.retire,self.clock=channel,runtime,current,retire,clock
        self.read_at=read_at if read_at is not None else material_read
        self.cancelled,self.retired,self.ready_for_completion=False,False,False
    def check(self,deadline):
        require(self.clock()<deadline,'transfer_deadline','transfer')
        self.runtime.require_armed();self.current()  # Fresh session + registry/owner guard required.
    def send_region(self,region,deadline):
        deadline=min(deadline,self.clock()+15)
        require(type(region.length)is int and 0<region.length<=131072,'transfer_size_bound','transfer')
        self.check(deadline);size=region.length
        control(self.channel,{'p12_length':size},self.clock,deadline)
        position=0
        try:
            while True:
                raw=receive(self.channel,self.clock,deadline,maximum=1024)
                command=json.loads(raw,object_pairs_hook=unique)
                require(type(command)is dict,'transfer_command_shape','transfer')
                if command=={'retire':True} and type(command['retire'])is bool:
                    self.retire();self.retired=True;self.cancelled=True
                    control(self.channel,{'retired':True},self.clock,deadline)
                    require(False,'transfer_cancelled','transfer')
                self.check(deadline)
                if command=={'complete':True} and type(command['complete'])is bool:
                    require(position==size,'transfer_premature_complete','transfer')
                    self.ready_for_completion=True;return
                require(set(command)=={'read'} and type(command['read'])is int
                        and 0<command['read']<=8192 and position<size,'transfer_read_scope','transfer')
                count=min(command['read'],size-position)
                block=self.read_at(region,position,count)
                require(type(block)is bytes and len(block)==count,'transfer_material_short_read','transfer')
                self.check(deadline)
                send(self.channel,b'B'+block,self.clock,deadline);position+=count;block=None
        except BaseException:
            if not self.retired:self.retire();self.retired=True
            raise


def serve_stream(channel,stream_call,runtime,current,retire,clock):
    """stream_call returns only after existing durable consume/cleanup completes.

    Do not acknowledge completion merely because last bytes were transmitted.
    Caller must kernel-authenticate this channel before invoking this function.
    """
    destination=PullDestination(channel,runtime,current,retire,clock)
    try:
        stream_call(destination)
        require(destination.ready_for_completion,'transfer_completion_missing','transfer')
        retire();destination.retired=True
        control(channel,{'complete':True,'retired':True},clock,clock()+1)
    finally:
        if not destination.retired:retire()

