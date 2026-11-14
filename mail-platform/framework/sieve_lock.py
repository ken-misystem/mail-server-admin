"""Build and validate the MIT Dovecot session-lock module for a matching native kit."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

MODULE='/usr/lib/dovecot/modules/lib90_mail_sieve_session_lock_plugin.so'
SOURCE='blueprint/native-sources/sieve_session_lock.c'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def validate(module, metadata, source):
    expected={'format','source_sha256','module_sha256','dovecot_config_sha256','dovecot_ABI'}
    if (type(metadata) is not dict or set(metadata)!=expected or
            type(metadata['format']) is not int or metadata['format']!=1):
        raise ValueError('sieve_lock_metadata')
    if metadata['source_sha256']!=sha(source) or metadata['module_sha256']!=sha(module):
        raise ValueError('sieve_lock_source_or_module_pin')
    if (len(module)<64 or module[:7]!=b'\x7fELF\x02\x01\x01' or
            struct.unpack_from('<HH',module,16)!=(3,62)):
        raise ValueError('sieve_lock_ELF_amd64_shared_object')
    if (not re.fullmatch('[a-f0-9]{64}',metadata['dovecot_config_sha256']) or
            not isinstance(metadata['dovecot_ABI'],str) or not metadata['dovecot_ABI'].startswith('2.4.')):
        raise ValueError('sieve_lock_build_binding')
    return metadata


def abi(tree):
    configuration=(tree/'config.h').read_bytes()
    match=re.search(rb'^#define DOVECOT_ABI_VERSION "([^"\r\n]+)"',configuration,re.M)
    if not match:
        raise ValueError('configured_Dovecot_ABI_missing')
    return configuration,match[1].decode('ascii')


def build(tree, source, output):
    tree,source,output=map(Path,(tree,source,output))
    configuration,version=abi(tree)
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    includes=[tree,*sorted(path for path in (tree/'src').iterdir() if path.is_dir())]
    destination=output/'sieve-session-lock.so'
    command=['/usr/bin/cc','-shared','-fPIC','-Wall','-Wextra','-Werror','-DHAVE_CONFIG_H',
             *(item for path in includes for item in ['-I',str(path)]),str(source),'-o',str(destination)]
    process=subprocess.run(command,capture_output=True,timeout=120)
    for name,raw in [('build.stdout',process.stdout),('build.stderr',process.stderr)]:
        (output/name).write_bytes(raw)
    (output/'build.json').write_text(json.dumps({'command':command,'exit':process.returncode,
        'source_sha256':sha(source.read_bytes())},indent=2)+'\n')
    if process.returncode:
        raise ValueError('sieve_lock_build_failed')
    metadata={'format':1,'source_sha256':sha(source.read_bytes()),'module_sha256':sha(destination.read_bytes()),
              'dovecot_config_sha256':sha(configuration),'dovecot_ABI':version}
    validate(destination.read_bytes(),metadata,source.read_bytes())
    destination.chmod(0o600)
    path=output/'sieve-session-lock.json'
    path.write_text(json.dumps(metadata,sort_keys=True,indent=2)+'\n')
    path.chmod(0o600)
    return metadata


def resources(inputs, source):
    from base_configuration import Resource
    module=inputs['sieve_session_lock']['bytes']
    raw=inputs['sieve_session_lock_metadata']['bytes']
    validate(module,json.loads(raw),source)
    return [Resource(MODULE,module,mode=0o644),
            Resource('/etc/mail-platform/sieve-lock.json',raw,mode=0o600)]


def main():
    parser=argparse.ArgumentParser()
    commands=parser.add_subparsers(dest='action',required=True)
    compiler=commands.add_parser('build')
    compiler.add_argument('--dovecot-build-tree',required=True,type=Path)
    compiler.add_argument('--source',required=True,type=Path)
    compiler.add_argument('--output',required=True,type=Path)
    admin=commands.add_parser('admin')
    admin.add_argument('--owner',required=True)
    admin.add_argument('operation',choices=('list','activate','deactivate','delete'))
    admin.add_argument('script',nargs='?')
    arguments=parser.parse_args()
    if arguments.action=='build':
        print(json.dumps(build(arguments.dovecot_build_tree,arguments.source,arguments.output)))
        return
    if (not re.fullmatch(r'[a-z0-9_.+-]{1,64}@[a-z0-9.-]{1,253}',arguments.owner) or
            (arguments.script is not None and (not 1<=len(arguments.script.encode())<=512 or
             any(ord(char)<32 or ord(char)==127 for char in arguments.script))) or
            ((arguments.operation in ('activate','delete'))!=(arguments.script is not None))):
        raise ValueError('sieve_admin_input')
    quoted='"'+(arguments.script or '').replace('\\','\\\\').replace('"','\\"')+'"'
    requests={'list':'LISTSCRIPTS','activate':'SETACTIVE '+quoted,
              'deactivate':'SETACTIVE ""','delete':'DELETESCRIPT '+quoted}
    # Root's pre-authenticated stdio entry uses the same ManageSieve user hooks.
    result=subprocess.run(['/usr/bin/doveadm','exec','managesieve','-u',arguments.owner],
                          input=(requests[arguments.operation]+'\r\nLOGOUT\r\n').encode(),
                          capture_output=True,timeout=30)
    import sys
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    if result.returncode:
        raise SystemExit(result.returncode)
    replies=result.stdout.splitlines()
    if any(line.startswith((b'NO ',b'BYE ')) for line in replies) or sum(line.startswith(b'OK') for line in replies)<2:
        raise SystemExit(75)


if __name__=='__main__':
    main()
