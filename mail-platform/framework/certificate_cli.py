"""Explicit root entrypoints for DNS-01, TLS publication and CA generations."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parent))
sys.path.append('/usr/lib/python3/dist-packages')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=('acme-worker','acme-configure','tls-deploy','tls-recover','ca-prepare','ca-activate','ca-retire','ca-rollback','ca-recover'))
    parser.add_argument('--rollback',action='store_true')
    parser.add_argument('--configuration',type=Path)
    parser.add_argument('--certificate',type=Path)
    parser.add_argument('--key',type=Path)
    parser.add_argument('--directory',type=Path)
    parser.add_argument('--issuer-id')
    parser.add_argument('--evidence',type=Path)
    parser.add_argument('--apply',action='store_true')
    args = parser.parse_args()
    if args.action == 'acme-worker':
        from acme_lifecycle import worker
        value = worker()
    else:
        if not args.apply:
            raise ValueError('certificate_apply_required')
        if args.action == 'acme-configure':
            if args.configuration is None or args.evidence is None:
                raise ValueError('ACME_configuration_new_evidence_required')
            from acme_lifecycle import register
            value = register(args.configuration,args.evidence)
        elif args.action in ('tls-recover','ca-recover'):
            if args.evidence is None:
                raise ValueError('TLS_new_recovery_evidence_required')
            if args.action=='tls-recover':
                from tls_deployment import recover
            else:
                from ca_rotation import recover
            value=recover(args.evidence,rollback=args.rollback)
        elif args.action == 'tls-deploy':
            if None in (args.certificate,args.key,args.evidence):
                raise ValueError('certificate_key_new_evidence_required')
            from tls_deployment import deploy
            value = deploy(args.certificate,args.key,args.evidence)
        elif args.action == 'ca-prepare':
            if args.directory is None:
                raise ValueError('CA_import_directory_required')
            from ca_rotation import prepare
            value = prepare(args.directory)
        else:
            if args.issuer_id is None or args.evidence is None:
                raise ValueError('CA_identity_new_evidence_required')
            from ca_rotation import switch
            value = switch(args.issuer_id,args.evidence,retire=args.action=='ca-retire',rollback=args.action=='ca-rollback')
    print(json.dumps(value,sort_keys=True))


if __name__ == '__main__':
    main()
