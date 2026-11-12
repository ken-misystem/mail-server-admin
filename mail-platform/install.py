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
    parser.add_argument('action', choices=['plan', 'stage', 'prepare', 'install'])
    parser.add_argument('--site', type=Path, required=True)
    parser.add_argument('--facts', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--kit', type=Path)
    parser.add_argument('--evidence', type=Path)
    parser.add_argument('--administrator-email')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--resolver', action='append', default=[])
    args = parser.parse_args()
    site = validate(json.loads(args.site.read_bytes()))
    verification = json.loads((ROOT / 'readiness.json').read_bytes())
    if args.action == 'plan':
        from host_install import plan as host_plan
        print(json.dumps({
            'status': 'candidate_only', 'target': 'Debian 13 amd64',
            'site': site, 'verification': verification, 'host_changes': False,
            'configuration_templates': describe(site),
            'host_installation': host_plan(ROOT, site),
        }, indent=2))
        return 0
    if args.action == 'install':
        if not args.apply:
            raise ValueError('apply_required')
        if args.kit is None or args.evidence is None or not args.administrator_email:
            raise ValueError('kit_evidence_and_administrator_required')
        if sys.platform != 'linux':
            raise ValueError('Debian_root_required')
        import getpass
        import warnings
        from host_install import Installer
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            password = getpass.getpass('New independent administrator password: ')
            repeat = getpass.getpass('Repeat password: ')
        installer = Installer(ROOT, site, args.kit, args.evidence, args.resolver)
        print(json.dumps(installer.run({'email': args.administrator_email, 'password': password, 'repeat': repeat})))
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
