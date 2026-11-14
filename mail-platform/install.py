"""Inspect, bind, and privately prepare a Debian 13 installation candidate."""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'payload/usr/local/lib/mail-platform-update'))
from configuration_templates import describe
from install_preparation import prepare, read_facts
from site_bindings import validate, render


def main():
    parser = argparse.ArgumentParser(description='Mail platform installation preparation')
    parser.add_argument('action', choices=['check', 'plan', 'stage', 'prepare', 'install', 'publish', 'reissue', 'acme-bootstrap'])
    parser.add_argument('--site', type=Path, required=True)
    parser.add_argument('--facts', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--kit', type=Path)
    parser.add_argument('--acme-config', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--administrator-email')
    parser.add_argument('--confirm-host')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--resolver', action='append', default=[])
    args = parser.parse_args()
    site = validate(json.loads(args.site.read_bytes()))
    verification = json.loads((ROOT / 'readiness.json').read_bytes())
    if args.action == 'acme-bootstrap':
        if not args.apply or None in (args.kit,args.acme_config,args.evidence):
            raise ValueError('ACME_apply_kit_configuration_new_evidence_required')
        from environment_check import inspect
        from host_install import CUSTOM_USERS
        report = inspect(ROOT,site,CUSTOM_USERS,args.evidence)
        if report['status'] != 'PASS':
            from environment_check import record_report
            record_report(args.evidence,report)
            print(json.dumps(report))
            return 2
        from acme_lifecycle import bootstrap
        print(json.dumps(bootstrap(args.acme_config,args.kit,args.evidence,install_dependencies=True)))
        return 0
    if args.action == 'check':
        from environment_check import inspect, record_report
        from host_install import CUSTOM_USERS
        result = inspect(ROOT, site, CUSTOM_USERS, args.evidence)
        if args.evidence is not None:
            record_report(args.evidence, result)
        print(json.dumps(result, indent=2))
        return 0 if result['status'] == 'PASS' else 2
    if args.action == 'plan':
        from host_install import plan as host_plan
        print(json.dumps({
            'status': 'candidate_only', 'target': 'Debian 13 amd64',
            'site': site, 'verification': verification, 'host_changes': False,
            'configuration_templates': describe(site),
            'host_installation': host_plan(ROOT, site),
            'distribution': json.loads((ROOT/'distribution-policy.json').read_bytes()),
        }, indent=2))
        return 0
    if args.action in ('publish', 'reissue'):
        if not args.apply or args.evidence is None:
            raise ValueError('apply_and_new_evidence_required')
        from setup_publication import execute
        if args.action == 'reissue':
            from setup_access import terminal_password, show_initial_access, ACCESS
            terminal, password = terminal_password()
            try:
                email = json.loads(ACCESS.read_bytes())['administrator']['email']
                result = execute(ROOT, site, args.evidence, 'reissue', password, password)
                show_initial_access(terminal, site['mail_host'], email, password)
                print(json.dumps(result))
            finally:
                password = None
                terminal.close()
        else:
            import getpass
            import warnings
            from setup_publication import root_json
            from setup_access import ACCESS
            password = repeat = None
            if root_json(ACCESS).get('phase') != 'complete':
                with warnings.catch_warnings():
                    warnings.simplefilter('error', getpass.GetPassWarning)
                    password = getpass.getpass('New permanent independent administrator password: ')
                    repeat = getpass.getpass('Repeat password: ')
            try:
                print(json.dumps(execute(ROOT, site, args.evidence, 'publish', password, repeat, args.confirm_host)))
            finally:
                password = repeat = None
        return 0
    if args.action == 'install':
        if not args.apply:
            raise ValueError('apply_required')
        if args.kit is None or args.evidence is None or not args.administrator_email:
            raise ValueError('kit_evidence_and_administrator_required')
        if sys.platform != 'linux':
            raise ValueError('Debian_root_required')
        from host_install import Installer
        from setup_access import terminal_password, show_initial_access
        installer = Installer(ROOT, site, args.kit, args.evidence, args.resolver)
        installer.acme_config = args.acme_config
        report = installer.check_environment()
        if report['status'] != 'PASS':
            from environment_check import record_report
            record_report(args.evidence, report)
            print(json.dumps(report, indent=2))
            return 2
        terminal, password = terminal_password()
        try:
            result = installer.run({'email': args.administrator_email, 'password': password, 'repeat': password})
            show_initial_access(terminal, site['mail_host'], args.administrator_email, password)
            print(json.dumps(result))
        finally:
            terminal.close()
            password = None
        return 0
    if args.output is None:
        raise ValueError('output_required')
    destination = args.output.absolute()
    payload = (ROOT / 'payload').resolve()
    if destination.exists() or destination == payload or payload in destination.parents:
        raise ValueError('unsafe_staging_directory')
    for path in ('/etc', '/usr', '/bin', '/sbin', '/boot', '/var/lib', '/var/spool'):
        if destination == Path(path) or Path(path) in destination.parents:
            raise ValueError('live_system_destination')
    if args.action == 'prepare':
        if args.facts is None:
            raise ValueError('target_facts_required')
        result = prepare(payload, site, read_facts(args.facts), destination)
    else:
        result = render(payload, site, destination)
        result = {'status': 'staged_only', 'files': result['files'], 'host_configured': False}
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (ValueError, OSError) as error:
        reason = str(error) if isinstance(error, ValueError) else 'filesystem_operation_failed'
        print(json.dumps({'status': 'refused', 'reason': reason}))
        raise SystemExit(2)
