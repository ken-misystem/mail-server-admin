"""Fixed production services; no existing service/namespace is broadened."""
ACCOUNT="mailantivirus"
AVROOT="/opt/mail-antivirus-v1"
AVCONFIG="/etc/mail-antivirus-v1"
AVSTATE="/var/lib/mail-antivirus-v1"
LIB="/usr/local/lib/mail-protection-admin-v1"
STATE="/var/lib/mail-protection-admin-v1"
CONFIG="/etc/mail-protection-admin-v1"
ENGINE="mail-protection-clamav-v1.service"
UPDATE="mail-protection-definitions-v1.service"
PUBLISH="mail-protection-publish-v1.service"
ADDED=(ENGINE,UPDATE,"mail-protection-definitions-v1.timer",PUBLISH,"mail-protection-publish-v1.timer")
HARDEN=("NoNewPrivileges=yes","CapabilityBoundingSet=","AmbientCapabilities=","PrivateTmp=yes","PrivateDevices=yes","ProtectSystem=strict","ProtectHome=yes","ProtectKernelTunables=yes","ProtectKernelModules=yes","ProtectKernelLogs=yes","ProtectControlGroups=yes","RestrictSUIDSGID=yes","RestrictNamespaces=yes","RestrictRealtime=yes","LockPersonality=yes","MemorySwapMax=0","LimitCORE=0","UMask=0077")
def unit(lines):return("\n".join(lines)+"\n").encode()
def units():
 native=["User="+ACCOUNT,"Group=111","SupplementaryGroups=","Slice=mail-protection-v1.slice",*HARDEN,"BindReadOnlyPaths="+AVROOT+"/runtime/usr/local:/usr/local","Environment=LD_LIBRARY_PATH=/usr/local/lib","ReadWritePaths="+AVSTATE+" /run/clamav","InaccessiblePaths=-/var/vmail -/var/mail -/var/spool/postfix -/var/lib/mysql -/run/mysqld -/etc/mail-feature-admin-v1","Nice=10","TasksMax=64"]
 return{
 "mail-protection-v1.slice":unit(["[Unit]","Description=Bounded antivirus resources","[Slice]","CPUQuota=200%","MemoryMax=3G","MemorySwapMax=0"]),
 ENGINE:unit(["[Unit]","Description=Managed ClamAV 1.4.6","After=local-fs.target","[Service]","Type=exec",*native,"PrivateNetwork=yes","RestrictAddressFamilies=AF_UNIX","RuntimeDirectory=clamav","RuntimeDirectoryMode=0750","ExecStart=/usr/bin/python3 -I -S -B "+AVROOT+"/identity_guard.py engine","MemoryMax=3G","TimeoutStartSec=120","TimeoutStopSec=30","Restart=on-failure","RestartSec=10","[Install]","WantedBy=multi-user.target"]),
 UPDATE:unit(["[Unit]","Description=Managed official antivirus definitions","After=network-online.target "+ENGINE,"[Service]","Type=oneshot",*native,"PrivateNetwork=no","RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6","ExecStart=/usr/bin/python3 -I -S -B "+AVROOT+"/identity_guard.py update","ExecStartPost=/usr/bin/python3 -I -S -B "+AVROOT+"/definition_status.py","MemoryMax=1G","TimeoutStartSec=600","TimeoutStopSec=30"]),
 "mail-protection-definitions-v1.timer":unit(["[Unit]","Description=Hourly official antivirus definition check","[Timer]","OnActiveSec=1h","OnUnitInactiveSec=1h","RandomizedDelaySec=5m","Unit="+UPDATE,"[Install]","WantedBy=timers.target"]),
 PUBLISH:unit(["[Unit]","Description=Apply typed antivirus and upstream SMTP settings","After=rspamd.service postfix.service "+ENGINE,"[Service]","Type=oneshot","User=root","Group=root","SupplementaryGroups=105 111",*HARDEN,"PrivateNetwork=yes","RestrictAddressFamilies=AF_UNIX","ExecStart=/usr/bin/python3 -I -S -B "+LIB+"/launch_publish.py","ReadWritePaths="+STATE+" /var/lib/mail-feature-admin-v1 /etc/postfix /etc/mail-client-certificates-v1 /etc/rspamd/lua.local.d /var/lib/mail-protection-public-v1 /run/lock","ReadOnlyPaths="+AVSTATE,"InaccessiblePaths=-/var/vmail -/var/mail -/var/spool/postfix -/var/lib/mysql -/etc/ssl/private","CPUQuota=100%","MemoryMax=256M","TasksMax=32","TimeoutStartSec=180","TimeoutStopSec=20"]),
 "mail-protection-publish-v1.timer":unit(["[Unit]","Description=Check pending protection settings","[Timer]","OnActiveSec=15s","OnUnitInactiveSec=15s","Unit="+PUBLISH,"[Install]","WantedBy=timers.target"])
 }
def configs():
 return{
 "clamd.conf":unit(["Foreground yes","User "+ACCOUNT,"DatabaseDirectory "+AVSTATE+"/definitions","OfficialDatabaseOnly yes","LocalSocket /run/clamav/clamd.ctl","LocalSocketMode 0660","LocalSocketGroup _rspamd","ConcurrentDatabaseReload no","MaxThreads 2","MaxQueue 4","StreamMaxLength 16M","MaxScanSize 100M","MaxFileSize 25M","MaxRecursion 16","MaxFiles 10000"]),
 "freshclam.conf":unit(["DatabaseDirectory "+AVSTATE+"/definitions","DatabaseOwner "+ACCOUNT,"DatabaseMirror database.clamav.net","DNSDatabaseInfo current.cvd.clamav.net","TestDatabases yes","MaxAttempts 1","ConnectTimeout 20","ReceiveTimeout 60","Foreground yes","NotifyClamd "+AVCONFIG+"/clamd.conf"])
 }
