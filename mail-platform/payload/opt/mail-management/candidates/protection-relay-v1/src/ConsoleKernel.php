<?php

declare(strict_types=1);

namespace MailServer\Management;

use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\SecurityBundle\SecurityBundle;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Kernel;
use Symfony\Component\Lock\LockFactory;
use Symfony\Component\Lock\Store\FlockStore;
use Symfony\Component\Routing\Loader\Configurator\RoutingConfigurator;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/** Local candidate only. No public entry point or production route is installed. */
final class ConsoleKernel extends Kernel
{
    use MicroKernelTrait;
    private const CACHE_LAYOUT = 'protection-relay-v3'; // Immutable release cache; never reuse an older container.

    public function __construct(
        private readonly AdminDirectory $directory,
        #[\SensitiveParameter] private readonly string $applicationSecret,
        private readonly string $stateDirectory,
        bool $test = false,
        private readonly ?AdminPasskeyStore $passkeys = null,
        private readonly ?AdminSettingsStore $settings = null,
        private readonly ?AdminOperationsStore $operations = null,
        private readonly ?OperationsStatusStore $operationsStatus = null,
        private readonly ?LogViewStore $logs = null,
        private readonly ?AdminAuditStore $audit = null,
        private readonly ?LegacySmtpStore $legacySmtp = null,
        private readonly ?CutoverStore $cutover = null,
        private readonly ?DomainDeliveryStore $domainDelivery = null,
        private readonly ?AccessBlacklistStore $accessBlacklist = null,
        private readonly ?SendLimitStore $sendLimits = null,
        private readonly ?QueueAdminStore $queueAdmin = null,
        private readonly ?OwnerStatusStore $ownerStatus = null,
        private readonly ?BulkMailboxStore $bulkMailbox = null,
        private readonly ?DomainDelegationStore $domainDelegation = null,
        private readonly ?ScopedAdminReadStore $scopedRead = null,
        private readonly ?ScopedWriteStore $scopedWrites = null,
        private readonly ?ForwardStore $forwardStore = null,
        private readonly ?ManagedSettingsStore $featureSettings = null,
        private readonly ?FeatureObservations $featureObservations = null,
        private readonly ?ProtectionStore $protectionStore = null,
    ) {
        if (strlen($applicationSecret) < 32) { throw new \DomainException('missing_application_secret'); }
        parent::__construct($test ? 'test' : 'prod', false);
    }

    public function registerBundles(): iterable { yield new FrameworkBundle(); yield new SecurityBundle(); }
    public function getProjectDir(): string { return dirname(__DIR__); }
    public function getCacheDir(): string { return $this->stateDirectory . '/cache-' . $this->environment . '-' . self::CACHE_LAYOUT; }
    public function getLogDir(): string { return $this->stateDirectory . '/logs'; }

    public function boot(): void
    {
        parent::boot();
        $this->getContainer()->set(AdminDirectory::class, $this->directory);
        $this->getContainer()->set(AdminPasskeyStore::class, $this->passkeys ?? new UnavailableAdminPasskeyStore());
        $this->getContainer()->set(AdminSettingsStore::class, $this->settings ?? new UnavailableAdminSettingsStore());
        $this->getContainer()->set(AdminOperationsStore::class, $this->operations ?? new UnavailableAdminOperationsStore());
        $this->getContainer()->set(OperationsStatusStore::class, $this->operationsStatus ?? new FileOperationsStatusStore());
        $this->getContainer()->set(LogViewStore::class, $this->logs ?? new FileLogViewStore());
        $this->getContainer()->set(AdminAuditStore::class, $this->audit ?? new UnavailableAdminAuditStore());
        $this->getContainer()->set(LegacySmtpStore::class, $this->legacySmtp ?? new UnavailableLegacySmtpStore());
        $this->getContainer()->set(CutoverStore::class, $this->cutover ?? new UnavailableCutoverStore());
        $this->getContainer()->set(SendLimitStore::class, $this->sendLimits ?? new UnavailableSendLimitStore());
        $this->getContainer()->set(QueueAdminStore::class, $this->queueAdmin ?? new UnixQueueAdminStore());
        $this->getContainer()->set(OwnerStatusStore::class, $this->ownerStatus ?? new UnixOwnerStatusStore());
        $this->getContainer()->set(BulkMailboxStore::class, $this->bulkMailbox ?? new UnavailableBulkMailboxStore());
        $this->getContainer()->set(DomainDelegationStore::class, $this->domainDelegation ?? new UnavailableDomainDelegationStore());
        $this->getContainer()->set(ScopedAdminReadStore::class, $this->scopedRead ?? new UnavailableScopedAdminReadStore());
        $this->getContainer()->set(ScopedWriteStore::class, $this->scopedWrites ?? new UnavailableScopedWriteStore());
        $this->getContainer()->set(ForwardStore::class, $this->forwardStore ?? new UnavailableForwardStore());
        $this->getContainer()->set(ManagedSettingsStore::class, $this->featureSettings ?? new UnavailableManagedSettingsStore());
        $this->getContainer()->set(FeatureObservations::class, $this->featureObservations ?? new UnavailableFeatureObservations());
        $this->getContainer()->set(ProtectionStore::class, $this->protectionStore ?? new UnixProtectionStore(new FeatureControlClient()));
        $this->getContainer()->set(AccessBlacklistStore::class, $this->accessBlacklist ?? new UnixAccessBlacklistStore());
        $this->getContainer()->set(DomainDeliveryStore::class, $this->domainDelivery ?? new UnavailableDomainDeliveryStore());
    }

    private function configureContainer(ContainerConfigurator $container): void
    {
        $container->extension('framework', [
            'secret' => $this->applicationSecret, 'http_method_override' => false,
            'trusted_hosts' => ['^mx\.mi-sys\.jp$'], 'csrf_protection' => true,
            'cache' => ['directory' => $this->stateDirectory . '/cache-data', 'pools' => [
                'cache.mail_admin_limiter' => ['adapter' => 'cache.adapter.filesystem']]],
            'rate_limiter' => ['mail_admin_scoped_write'=>['policy'=>'fixed_window','limit'=>30,'interval'=>'1 minute','cache_pool'=>'cache.mail_admin_limiter','lock_factory'=>'mail_admin_lock_factory'], 'mail_admin_delegation'=>['policy'=>'fixed_window','limit'=>20,'interval'=>'1 minute','cache_pool'=>'cache.mail_admin_limiter','lock_factory'=>'mail_admin_lock_factory'], 'mail_admin_scoped'=>['policy'=>'fixed_window','limit'=>120,'interval'=>'1 minute','cache_pool'=>'cache.mail_admin_limiter','lock_factory'=>'mail_admin_lock_factory'], 'mail_admin_bulk'=>['policy'=>'fixed_window','limit'=>5,'interval'=>'1 minute','cache_pool'=>'cache.mail_admin_limiter','lock_factory'=>'mail_admin_lock_factory'], 'mail_admin_owner'=>['policy'=>'fixed_window','limit'=>30,'interval'=>'1 minute','cache_pool'=>'cache.mail_admin_limiter','lock_factory'=>'mail_admin_lock_factory'], 'mail_admin_queue'=>['policy'=>'fixed_window','limit'=>20,'interval'=>'1 minute','cache_pool'=>'cache.mail_admin_limiter','lock_factory'=>'mail_admin_lock_factory'], 'mail_admin_send_limits'=>['policy'=>'fixed_window','limit'=>20,'interval'=>'1 minute','cache_pool'=>'cache.mail_admin_limiter','lock_factory'=>'mail_admin_lock_factory'], 'mail_admin_access' => ['policy' => 'fixed_window', 'limit' => 20, 'interval' => '1 minute', 'cache_pool' => 'cache.mail_admin_limiter', 'lock_factory' => 'mail_admin_lock_factory'], 'mail_admin_domain_delivery'=>['policy'=>'fixed_window','limit'=>20,'interval'=>'1 minute','cache_pool'=>'cache.mail_admin_limiter','lock_factory'=>'mail_admin_lock_factory'],'mail_admin_cutover'=>['policy'=>'fixed_window','limit'=>20,'interval'=>'1 minute','cache_pool'=>'cache.mail_admin_limiter','lock_factory'=>'mail_admin_lock_factory'],'mail_admin_legacy_smtp' => ['policy' => 'fixed_window', 'limit' => 20, 'interval' => '1 minute', 'cache_pool' => 'cache.mail_admin_limiter', 'lock_factory' => 'mail_admin_lock_factory'], 'mail_admin_audit' => ['policy' => 'fixed_window', 'limit' => 20, 'interval' => '1 minute', 'cache_pool' => 'cache.mail_admin_limiter', 'lock_factory' => 'mail_admin_lock_factory'], 'mail_admin_logs' => ['policy' => 'fixed_window', 'limit' => 20, 'interval' => '1 minute', 'cache_pool' => 'cache.mail_admin_limiter', 'lock_factory' => 'mail_admin_lock_factory'], 'mail_admin_operation' => ['policy' => 'fixed_window', 'limit' => 30,
                'interval' => '1 minute', 'cache_pool' => 'cache.mail_admin_limiter', 'lock_factory' => 'mail_admin_lock_factory'],
                'mail_admin_factor' => ['policy' => 'fixed_window',
                'limit' => 10, 'interval' => '1 minute', 'cache_pool' => 'cache.mail_admin_limiter',
                'lock_factory' => 'mail_admin_lock_factory']],
            'session' => [
                'storage_factory_id' => $this->environment === 'test'
                    ? 'session.storage.factory.mock_file' : 'session.storage.factory.native',
                'handler_id' => null, 'save_path' => $this->stateDirectory . '/sessions',
                'name' => 'MAILADMINSESSID', 'cookie_path' => '/mail-admin',
                'cookie_secure' => true, 'cookie_httponly' => true, 'cookie_samesite' => 'strict',
                'gc_maxlifetime' => 1800,
            ],
        ]);
        $container->extension('security', [
            'password_hashers' => [AdminUser::class => ['algorithm' => 'native']],
            'session_fixation_strategy' => 'migrate',
            'providers' => ['mail_admins' => ['id' => AdminUserProvider::class]],
            'firewalls' => ['mail_admin' => [
                'pattern' => '^/mail-admin(?:/|$)', 'provider' => 'mail_admins',
                'user_checker' => AdminUserChecker::class,
                'custom_authenticators' => [AdminPasskeyAuthenticator::class],
                'login_throttling' => ['max_attempts' => 5, 'interval' => '1 minute',
                    'cache_pool' => 'cache.mail_admin_limiter', 'lock_factory' => 'mail_admin_lock_factory'],
                'form_login' => [
                    'login_path' => 'mail_admin_login', 'check_path' => 'mail_admin_login',
                    'enable_csrf' => true, 'csrf_token_id' => 'mail_admin_login', 'form_only' => true,
                    'default_target_path' => 'mail_admin_home', 'always_use_default_target_path' => true,
                ],
                'logout' => ['path' => 'mail_admin_logout', 'target' => 'mail_admin_login',
                    'enable_csrf' => true, 'csrf_token_id' => 'mail_admin_logout'],
            ]],
            'access_control' => [
                ['path' => '^/mail-admin/(?:login(?:/passkey/(?:options|finish))?|passkey-login\.js)$', 'roles' => 'PUBLIC_ACCESS', 'requires_channel' => 'https'],
                ['path' => '^/mail-admin(?:/|$)', 'roles' => 'ROLE_MAIL_ADMIN', 'requires_channel' => 'https'],
            ],
        ]);
        $services = $container->services();
        $services->set(ScopedWriteStore::class)->synthetic()->public();
        $services->set(ScopedOperationsController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(ScopedAdminReadStore::class),service(ScopedWriteStore::class),service('limiter.mail_admin_scoped_write')]);
        $services->set(ForwardStore::class)->synthetic()->public();
        $services->set(ManagedSettingsStore::class)->synthetic()->public();
        $services->set(FeatureObservations::class)->synthetic()->public();
        $services->set(ProtectionStore::class)->synthetic()->public();
        $services->set(ProtectionController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(ProtectionStore::class),service('limiter.mail_admin_scoped_write')]);
        $services->set(UpdateClient::class)->public();
        $services->set(UpdateController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(UpdateClient::class),service('limiter.mail_admin_scoped_write')]);
        $services->set(ManagedSettingsController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(ManagedSettingsStore::class),service('limiter.mail_admin_scoped_write')]);
        $services->set(FeatureRuntimeController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(FeatureObservations::class)]);
        $services->set(ForwardController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(ForwardStore::class),service('limiter.mail_admin_scoped_write')]);
        $services->set(DomainDelegationStore::class)->synthetic()->public();
        $services->set(ScopedAdminReadStore::class)->synthetic()->public();
        $services->set(DomainDelegationController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(DomainDelegationStore::class),service('limiter.mail_admin_delegation')]);
        $services->set(ScopedAdminController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(ScopedAdminReadStore::class),service('limiter.mail_admin_scoped')]);
        $services->set(BulkMailboxStore::class)->synthetic()->public();
        $services->set(BulkMailboxController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(BulkMailboxStore::class),service('limiter.mail_admin_bulk')]);
        $services->set(OwnerStatusStore::class)->synthetic()->public();
        $services->set(OwnerStatusController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(OwnerStatusStore::class),service('limiter.mail_admin_owner')]);
        $services->set(QueueAdminStore::class)->synthetic()->public();
        $services->set(QueueAdminController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(QueueAdminStore::class),service('limiter.mail_admin_queue')]);
        $services->set(AdminDirectory::class)->synthetic()->public();
        $services->set(AdminPasskeyStore::class)->synthetic()->public();
        $services->set(AdminSettingsStore::class)->synthetic()->public();
        $services->set(AdminOperationsStore::class)->synthetic()->public();
        $services->set(OperationsStatusStore::class)->synthetic()->public();
        $services->set(LogViewStore::class)->synthetic()->public();
        $services->set(LegacySmtpStore::class)->synthetic()->public();
        $services->set(CutoverStore::class)->synthetic()->public();
        $services->set(SendLimitStore::class)->synthetic()->public();
        $services->set(SendLimitController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(SendLimitStore::class),service('limiter.mail_admin_send_limits')]);
        $services->set(AccessBlacklistStore::class)->synthetic()->public();
        $services->set(AccessBlacklistController::class)->public()->args([service('security.token_storage'), service('security.csrf.token_manager'), service(AccessBlacklistStore::class), service('limiter.mail_admin_access')]);
        $services->set(DomainDeliveryStore::class)->synthetic()->public();
        $services->set(DomainDeliveryStatus::class);
        $services->set(DomainDeliveryController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(DomainDeliveryStore::class),service(DomainDeliveryStatus::class),service('limiter.mail_admin_domain_delivery')]);
        $services->set(CutoverController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(CutoverStore::class),service('limiter.mail_admin_cutover')]);
        $services->set(DomainAliasController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(CutoverStore::class),service('limiter.mail_admin_cutover')]);
        $services->set(LegacySmtpController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(LegacySmtpStore::class),service('limiter.mail_admin_legacy_smtp')]);
        $services->set(AdminAuditStore::class)->synthetic()->public();
        $services->set(AdminAuditController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(AdminAuditStore::class),service('limiter.mail_admin_audit')]);
        $services->set(LogViewController::class)->public()->args([service('security.token_storage'),service('security.csrf.token_manager'),service(LogViewStore::class),service('limiter.mail_admin_logs')]);
        $services->set(OperationsStatusController::class)->public()->args([service('security.token_storage'),
            service('security.csrf.token_manager'), service(OperationsStatusStore::class)]);
        $services->set(AdminOperationsController::class)->public()->args([service('security.token_storage'),
            service('security.csrf.token_manager'), service(AdminOperationsStore::class), service('limiter.mail_admin_operation')]);
        $services->set(AdminSettingsController::class)->public()->args([
            service('security.token_storage'), service('security.csrf.token_manager'), service(AdminSettingsStore::class)]);
        $services->set('mail_admin_lock_store', FlockStore::class)->args([$this->stateDirectory . '/locks']);
        $services->set('mail_admin_lock_factory', LockFactory::class)->args([service('mail_admin_lock_store')]);
        $services->set(AdminWebauthn::class);
        $services->set(AdminPasskeyCeremony::class)->args([service(AdminPasskeyStore::class), service(AdminWebauthn::class)]);
        $services->set(AdminPasskeyLogin::class)->public()->args([service(AdminDirectory::class), service(AdminPasskeyStore::class),
            service(AdminWebauthn::class), service('security.csrf.token_manager'), service('limiter.mail_admin_factor')]);
        $services->set(AdminPasskeyAuthenticator::class)->args([service(AdminPasskeyLogin::class)]);
        $services->set(AdminPasswordLoginListener::class)->tag('kernel.event_listener', [
            'event' => 'Symfony\\Component\\Security\\Http\\Event\\LoginSuccessEvent',
            'method' => 'onLogin', 'dispatcher' => 'security.event_dispatcher.mail_admin']);
        $services->set(AdminUserProvider::class)->args([service(AdminDirectory::class)]);
        $services->set(AdminUserChecker::class);
        $services->set(ConsoleController::class)->public()->args([
            service('security.token_storage'), service('security.csrf.token_manager'),
            service(AdminPasskeyCeremony::class), service('limiter.mail_admin_factor'),
        ]);
    }

    private function configureRoutes(RoutingConfigurator $routes): void
    {
        $routes->add('mail_admin_guest_passkey_options', '/mail-admin/login/passkey/options')->methods(['POST'])
            ->controller(AdminPasskeyLogin::class . '::options');
        $routes->add('mail_admin_guest_passkey_finish', '/mail-admin/login/passkey/finish')->methods(['POST'])
            ->controller(ConsoleController::class . '::passkeyLoginFallback');
        $routes->add('mail_admin_guest_passkey_script', '/mail-admin/passkey-login.js')->methods(['GET'])
            ->controller(ConsoleController::class . '::passkeyScript');
        $routes->add('mail_admin_feature_settings_read','/mail-admin/feature-settings/{kind}')->requirements(['kind'=>'access|spam'])->methods(['GET'])->controller(ManagedSettingsController::class.'::show');
        $routes->add('mail_admin_feature_settings_save','/mail-admin/feature-settings/{kind}')->requirements(['kind'=>'access|spam'])->methods(['POST'])->controller(ManagedSettingsController::class.'::save');
        $routes->add('mail_admin_updates','/mail-admin/updates')->methods(['GET'])->controller(UpdateController::class.'::show');
        $routes->add('mail_admin_updates_save','/mail-admin/updates')->methods(['POST'])->controller(UpdateController::class.'::save');
        $routes->add('mail_admin_protection_read','/mail-admin/protection/{kind}')->requirements(['kind'=>'scanner|upstream'])->methods(['GET'])->controller(ProtectionController::class.'::show');
        $routes->add('mail_admin_protection_save','/mail-admin/protection/{kind}')->requirements(['kind'=>'scanner|upstream'])->methods(['POST'])->controller(ProtectionController::class.'::save');
        $routes->add('mail_admin_feature_status','/mail-admin/feature-status/{section}')->requirements(['section'=>implode('|',array_keys(FeatureRuntimeController::TITLES))])->methods(['GET'])->controller(FeatureRuntimeController::class.'::show');
        $routes->add('mail_admin_forward_edit','/mail-admin/forward/{id}')->requirements(['id'=>'[1-9][0-9]{0,19}'])->methods(['GET'])->controller(ForwardController::class.'::edit');
        $routes->add('mail_admin_forward_save','/mail-admin/forward/{id}')->requirements(['id'=>'[1-9][0-9]{0,19}'])->methods(['POST'])->controller(ForwardController::class.'::save');
        $routes->add('mail_admin_scoped_create','/mail-admin/scoped/create/{kind}')->requirements(['kind'=>'mailbox|alias'])->methods(['GET'])->controller(ScopedOperationsController::class.'::create');
        $routes->add('mail_admin_scoped_edit','/mail-admin/scoped/edit/{kind}/{id}')->requirements(['kind'=>'mailbox|alias','id'=>'[1-9][0-9]{0,19}'])->methods(['GET'])->controller(ScopedOperationsController::class.'::edit');
        $routes->add('mail_admin_scoped_operation','/mail-admin/scoped/operation/{action}')->requirements(['action'=>implode('|',array_keys(ScopedMutation::OPERATIONS))])->methods(['POST'])->controller(ScopedOperationsController::class.'::apply');
        $routes->add('mail_admin_delegation','/mail-admin/delegation')->methods(['GET'])->controller(DomainDelegationController::class.'::show');
        $routes->add('mail_admin_delegation_save','/mail-admin/delegation/save')->methods(['POST'])->controller(DomainDelegationController::class.'::save');
        $routes->add('mail_admin_scoped','/mail-admin/scoped')->methods(['GET'])->controller(ScopedAdminController::class.'::home');
        $routes->add('mail_admin_scoped_list','/mail-admin/scoped/{section}')->requirements(['section'=>'mailboxes|aliases|forwards|usage'])->methods(['GET'])->controller(ScopedAdminController::class.'::show');
        $routes->add('mail_admin_scoped_api','/mail-admin/scoped/api/{section}')->requirements(['section'=>'mailboxes|aliases|forwards|usage'])->methods(['GET'])->controller(ScopedAdminController::class.'::api');
        $routes->add('mail_admin_scoped_record','/mail-admin/scoped/api/{section}/{id}')->requirements(['section'=>'mailboxes|aliases|forwards|usage','id'=>'[1-9][0-9]{0,19}'])->methods(['GET'])->controller(ScopedAdminController::class.'::api');
        $routes->add('mail_admin_bulk','/mail-admin/bulk')->methods(['GET'])->controller(BulkMailboxController::class.'::show');
        $routes->add('mail_admin_bulk_preview','/mail-admin/bulk/preview')->methods(['POST'])->controller(BulkMailboxController::class.'::submit');
        $routes->add('mail_admin_bulk_apply','/mail-admin/bulk/apply')->methods(['POST'])->controller(BulkMailboxController::class.'::submit');
        $routes->add('mail_admin_owner_status','/mail-admin/send-status')->methods(['GET'])->controller(OwnerStatusController::class.'::show');
        $routes->add('mail_admin_owner_stop','/mail-admin/send-status/stop')->methods(['POST'])->controller(OwnerStatusController::class.'::stop');
        $routes->add('mail_admin_queue','/mail-admin/queue')->methods(['GET'])->controller(QueueAdminController::class.'::show');
        $routes->add('mail_admin_queue_action','/mail-admin/queue/action')->methods(['POST'])->controller(QueueAdminController::class.'::apply');
        $routes->add('mail_admin_send_limits', '/mail-admin/send-limits')->methods(['GET','POST'])->controller(SendLimitController::class.'::show');
        $routes->add('mail_admin_access', '/mail-admin/access-blacklist')->methods(['GET'])->controller(AccessBlacklistController::class . '::show');
        $routes->add('mail_admin_access_release', '/mail-admin/access-blacklist/release')->methods(['POST'])->controller(AccessBlacklistController::class . '::release');
        $routes->add('mail_admin_login', '/mail-admin/login')->methods(['GET', 'POST'])
            ->controller(ConsoleController::class . '::login');
        $routes->add('mail_admin_logout', '/mail-admin/logout')->methods(['POST']);
        $routes->add('mail_admin_home', '/mail-admin/')->methods(['GET'])
            ->controller(ConsoleController::class . '::home');
        $routes->add('mail_admin_manage', '/mail-admin/manage')->methods(['GET'])
            ->controller(AdminSettingsController::class . '::show');
        $routes->add('mail_admin_legacy_smtp','/mail-admin/legacy-smtp')->methods(['GET','POST'])->controller(LegacySmtpController::class.'::show');
        $routes->add('mail_admin_domain_delivery', '/mail-admin/domain-delivery')->methods(['GET','POST'])->controller(DomainDeliveryController::class.'::show');
        $routes->add('mail_admin_domain_aliases', '/mail-admin/domain-aliases')->methods(['GET','POST'])->controller(DomainAliasController::class.'::show');
        $routes->add('mail_admin_quota', '/mail-admin/{section}')->requirements(['section'=>'mailbox-quota'])->methods(['GET','POST'])->controller(CutoverController::class.'::show');
        $routes->add('mail_admin_audit', '/mail-admin/audit')->methods(['GET','POST'])->controller(AdminAuditController::class.'::show');
        $routes->add('mail_admin_logs', '/mail-admin/logs')->methods(['GET','POST'])->controller(LogViewController::class.'::show');
        $routes->add('mail_admin_operations_status', '/mail-admin/operations-status')->methods(['GET'])
            ->controller(OperationsStatusController::class . '::show');
        $routes->add('mail_admin_user_policy', '/mail-admin/user-policy')->methods(['POST'])
            ->controller(AdminSettingsController::class . '::save');
        $routes->add('mail_admin_operation', '/mail-admin/operation/{action}')->methods(['POST'])
            ->requirements(['action' => implode('|', AdminMutation::ACTIONS)])
            ->controller(AdminOperationsController::class . '::apply');
        $routes->add('mail_admin_passkey_options', '/mail-admin/passkey/{kind}/options')
            ->requirements(['kind' => 'register|assert'])->methods(['POST'])
            ->controller(ConsoleController::class . '::passkeyOptions');
        $routes->add('mail_admin_passkey_finish', '/mail-admin/passkey/{kind}/finish')
            ->requirements(['kind' => 'register|assert'])->methods(['POST'])
            ->controller(ConsoleController::class . '::passkeyFinish');
        $routes->add('mail_admin_passkey_script', '/mail-admin/passkey.js')->methods(['GET'])
            ->controller(ConsoleController::class . '::passkeyScript');
    }
}
