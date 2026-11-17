"""Fixed component hooks for initial adoption after independent preflight.

Caller-supplied preflight/verification readers may reject; they must not mutate.
The only commands here are systemd, local syntax checks and plugin registration.
"""
from pathlib import Path
import os

from adoption_services import ServiceBarrier
from host_transaction import Commands
from policy_binding import ensure_directories
from roundcube_migration import SettingsMigration, require_web_quiet
from roundcube_plugins import PluginLinks
from certificate_state import certificate_lock


class AdoptionHost:
    def __init__(self, evidence, contract, installed, preflight, verification, protection=None, enrollment=None, sieve_layout=None):
        self.path = Path(evidence)
        self.commands = Commands(self.path)
        self.barrier = ServiceBarrier(self.path, contract, installed, self.commands)
        self.links = PluginLinks('/', self.path/'plugin-links.json')
        self.preflight_reader = preflight
        self.verification_reader = verification
        self.lock = None
        self.protection = protection
        self.enrollment = enrollment
        self.sieve_layout = sieve_layout

    def sieve_check(self,stage,installed=False):
        if self.sieve_layout is not None:
            from adoption_sieve import verify_effective
            return verify_effective(self.sieve_layout,self.commands,stage,installed=installed)

    def protect(self, stage):
        if self.protection is not None and self.protection(stage).get('status') != 'PASS':
            raise ValueError('adoption_host_protection_failed')

    def acquire_lock(self):
        if self.lock is None:
            lock = certificate_lock()
            lock.__enter__()
            self.lock = lock

    def release_lock(self):
        if self.lock is not None:
            self.lock.__exit__(None, None, None)
            self.lock = None

    def preflight(self, plan, content):
        require_web_quiet(self.path, allow_active=True)
        self.protect('preflight')
        self.sieve_check('preflight')
        result = self.preflight_reader(plan, content)
        if result.get('status') != 'PASS':
            raise ValueError('adoption_host_preflight_failed')
        self.barrier.snapshot()
        if self.enrollment is not None:self.enrollment.preflight()
        return result

    def quiesce(self):
        self.protect('before_quiesce')
        result = self.barrier.quiesce()
        self.protect('quiesced')
        self.sieve_check('quiesced')
        require_web_quiet(self.path)
        self.acquire_lock()
        return result

    def health(self):
        self.protect('candidate')
        # Daemons remain stopped. Functional checks occur after resume and cannot
        # cause an automatic rollback of traffic or newly published state.
        require_web_quiet(self.path)
        pending = self.commands.run('certificate_downloads', ['/usr/bin/mariadb', '--no-defaults',
            '--batch', '--skip-column-names', '--protocol=socket', '--user=root'],
            data=b"SET SESSION time_zone='+00:00';START TRANSACTION READ ONLY;SELECT COUNT(*) FROM mail_management.mail_client_downloads WHERE state IN ('ready','consumed','unknown') AND expires_at>UTC_TIMESTAMP();COMMIT;")
        if pending.strip() != b'0':
            raise ValueError('adoption_certificate_downloads_pending')
        self.commands.run('Dovecot_syntax', ['/usr/bin/doveconf', '-n'])
        self.sieve_check('candidate',installed=True)
        self.commands.run('Postfix_syntax', ['/usr/sbin/postconf', '-n'])
        self.commands.run('Roundcube_PHP_syntax', ['/usr/bin/php8.4', '-l', '/etc/roundcube/config.inc.php'])
        self.commands.run('FPM_syntax', ['/usr/sbin/php-fpm8.4', '-t'])
        ensure_directories()
        lock = Path('/var/lib/roundcube/mail-settings-locks')
        if SettingsMigration.lock_state(lock) is None:
            lock.mkdir(mode=0o700)
            fd = os.open(lock, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fchown(fd, 33, 33); os.fchmod(fd, 0o700)
            finally:
                os.close(fd)
        SettingsMigration.lock_state(lock)
        self.links.apply(['mail_settings'])
        return {'status':'PASS','syntax':True,'plugin_link':True,'service_health':'pending_resume'}

    def resume(self):
        self.protect('before_resume')
        self.release_lock()
        result = self.barrier.resume()
        self.protect('resumed')
        if self.enrollment is not None:result['enrollment']=self.enrollment.activate()
        return result

    def verify(self):
        self.protect('verify')
        self.barrier.verify()
        self.sieve_check('verify',installed=True)
        if self.enrollment is not None:self.enrollment.verify()
        result = self.verification_reader()
        if result.get('status') != 'PASS':
            raise ValueError('adoption_host_verification_failed')
        return result

    def recovery_preflight(self, record):
        self.protect('recovery')
        self.barrier.recovery_preflight(record)
        if record['phase'] == 'barrier_requested':
            # The file engine cannot have written any candidate at this phase.
            # A failed drain can leave FPM active; restore only original services.
            if (self.path/'plugin-links.json').exists():
                raise ValueError('adoption_partial_barrier_plugin_journal')
            return {'status':'PASS','scope':'partial_barrier_before_file_writes'}
        require_web_quiet(self.path)
        self.acquire_lock()
        result = self.links.restore()
        if result.get('held'):
            raise ValueError('adoption_plugin_recovery_held')
        return {'status':'PASS'}

    def restore_resume(self):
        self.protect('before_restore_resume')
        self.release_lock()
        result = self.barrier.resume(restored=True)
        self.protect('restored')
        return result
