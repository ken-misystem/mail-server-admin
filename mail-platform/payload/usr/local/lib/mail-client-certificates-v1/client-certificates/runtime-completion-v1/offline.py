"""CA export/restore/physical-custody evidence. No default approval or key output."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import time
import uuid
from safety import need,held

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def write_new(path,raw,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_CLOEXEC',0),mode)
    try:need(os.write(fd,raw)==len(raw),'custody_export_write');os.fsync(fd)
    finally:os.close(fd)
    return sha256(raw).hexdigest()
def restoration(result):
    need(type(result)is dict and set(result)=={'ok','issuer_id','root_sha256','issuer_sha256','backup_sha256','restore_verified','protection'}
        and result['ok']is True and result['restore_verified']is True,'custody_restore_record')
    need(str(uuid.UUID(result['issuer_id']))==result['issuer_id']and all(re.fullmatch('[0-9a-f]{64}',result[k])for k in('root_sha256','issuer_sha256','backup_sha256')),'custody_restore_binding')
    return {'version':1,'issuer_id':result['issuer_id'],'root_certificate_sha256':result['root_sha256'],
        'issuer_certificate_sha256':result['issuer_sha256'],'encrypted_backup_sha256':result['backup_sha256'],'restore_verified':True}
def acknowledge(receipt,statement,for_startup=False):
    need(type(receipt)is dict and receipt.get('version')==1 and receipt.get('restore_verified')is True,'custody_restoration_required')
    need(type(statement)is dict and set(statement)=={'version','restore_receipt_sha256','capsule_on_offline_medium','recovery_on_separate_offline_medium','operator_confirmed_at'}
        and statement['version']==1 and statement['restore_receipt_sha256']==sha256(canonical(receipt)).hexdigest()
        and statement['capsule_on_offline_medium']is True and statement['recovery_on_separate_offline_medium']is True
        and type(statement['operator_confirmed_at'])is int and statement['operator_confirmed_at']>0
        and 0<=time.time()-statement['operator_confirmed_at'] and(for_startup or time.time()-statement['operator_confirmed_at']<=86400),'custody_physical_confirmation_required')
    return {'issuer_id':receipt['issuer_id'],'issuer_certificate_sha256':receipt['issuer_certificate_sha256'],
        'root_certificate_sha256':receipt['root_certificate_sha256'],'encrypted_backup_sha256':receipt['encrypted_backup_sha256'],
        'restore_evidence_sha256':sha256(canonical(receipt)).hexdigest(),'offline_custodian_acknowledged':True}
def validate(custody,receipt,statement):
    expected=acknowledge(receipt,statement,True);need(custody==expected,'custody_saved_ack_mismatch');return expected

def dpapi(raw,protect):
    """Current-user Windows DPAPI, UI forbidden. No fallback to clear recovery key."""
    need(os.name=='nt'and type(raw)is bytes and 0<len(raw)<=131072,'windows_dpapi_input')
    import ctypes
    from ctypes import wintypes
    class Blob(ctypes.Structure):_fields_=[('cbData',wintypes.DWORD),('pbData',ctypes.POINTER(ctypes.c_ubyte))]
    buffer=(ctypes.c_ubyte*len(raw)).from_buffer_copy(raw);source=Blob(len(raw),ctypes.cast(buffer,ctypes.POINTER(ctypes.c_ubyte)));target=Blob()
    api=ctypes.WinDLL('crypt32',use_last_error=True);kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.LocalFree.argtypes=[wintypes.HLOCAL];kernel.LocalFree.restype=wintypes.HLOCAL
    function=api.CryptProtectData if protect else api.CryptUnprotectData
    function.restype=wintypes.BOOL
    if protect:
        function.argtypes=[ctypes.POINTER(Blob),wintypes.LPCWSTR,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
        ok=function(ctypes.byref(source),'Mail client CA recovery v1',None,None,None,1,ctypes.byref(target))
    else:
        function.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
        ok=function(ctypes.byref(source),None,None,None,None,1,ctypes.byref(target))
    try:
        if not ok:raise OSError(ctypes.get_last_error(),'windows_dpapi_failed')
        need(0<target.cbData<=131072,'windows_dpapi_output_bound');return ctypes.string_at(target.pbData,target.cbData)
    finally:
        ctypes.memset(buffer,0,len(raw))
        if target.pbData:ctypes.memset(target.pbData,0,target.cbData);kernel.LocalFree(target.pbData)

def receive_windows(capsule,key,directory,recovery_directory):
    """Explicit external destinations, one-use files. Caller must enforce ACL first.

    Local encrypted storage is NOT physical offline custody. Raw key is never a
    filesystem output. DPAPI protects against a different Windows account; it is
    not protection from a process running as this signed-in user.
    """
    need(os.name=='nt'and type(capsule)is bytes and 0<len(capsule)<=98304 and type(key)is bytes and len(key)==32,'windows_custody_transfer')
    left,right=Path(directory),Path(recovery_directory)
    need(left.is_absolute()and right.is_absolute()and left!=right and left.exists()and right.exists(),'separate_existing_custody_destinations')
    for parent in (left,right):
        for part in(parent,*parent.parents):
            info=part.lstat();need(not getattr(info,'st_file_attributes',0)&0x400,'windows_custody_reparse_point')
    encrypted=dpapi(key,True);need(dpapi(encrypted,False)==key,'windows_dpapi_readback')
    identity=str(uuid.uuid4());capsule_path=left/(identity+'.ca-backup.json');key_path=right/(identity+'.recovery.dpapi')
    cap_pin=write_new(capsule_path,capsule);key_pin=write_new(key_path,encrypted)
    need(capsule_path.read_bytes()==capsule and key_path.read_bytes()==encrypted,'windows_export_readback')
    return {'version':1,'transfer_id':identity,'capsule_sha256':cap_pin,'protected_recovery_sha256':key_pin,
        'physical_offline_custody_confirmed':False,'partial_files_on_failure_retained':True}

def portable_recovery(key,issuer_id,backup_pin,directory):
    """Operator-selected removable recovery medium, separate from the capsule.

    This small secret file is a physical recovery key. It is NOT a root private
    key or an online server credential. No automatic destination or auto-eject.
    Physical separation/unmount requires a separate operator attestation.
    """
    need(os.name=='nt'and type(key)is bytes and len(key)==32,'portable_recovery_input')
    need(str(uuid.UUID(issuer_id))==issuer_id and re.fullmatch('[0-9a-f]{64}',backup_pin)is not None,'portable_recovery_binding')
    path=Path(directory);need(path.is_absolute()and path.is_dir(),'portable_recovery_directory')
    import ctypes
    from ctypes import wintypes
    api=ctypes.WinDLL('kernel32',use_last_error=True);api.GetDriveTypeW.argtypes=[wintypes.LPCWSTR];api.GetDriveTypeW.restype=wintypes.UINT
    need(api.GetDriveTypeW(path.anchor)==2,'portable_recovery_requires_removable_medium')
    for part in(path,*path.parents):need(not getattr(part.lstat(),'st_file_attributes',0)&0x400,'portable_recovery_reparse_point')
    import base64
    raw=canonical({'version':1,'issuer_id':issuer_id,'encrypted_backup_sha256':backup_pin,'recovery_key':base64.b64encode(key).decode()})
    target=path/(issuer_id+'.ca-recovery.json');pin=write_new(target,raw)
    need(target.read_bytes()==raw,'portable_recovery_readback');return {'sha256':pin,'portable_readback_verified':True,'physical_offline_confirmed':False}
