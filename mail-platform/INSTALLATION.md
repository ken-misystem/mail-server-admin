# Debian 13新規導入候補

## 監視参照の環境設定（未公開の共通修正）

監視用Postfix設定ディレクトリとCertbotの証明書lineageは、コードと分離した `/etc/mail-management-operations-v1/environment.json` で管理する。新規導入では専用Postfix設定と入力したmail_hostのlineageを設定する。既存ファイルがある場合は新規導入で置換せず、初回移行手順を要求する。

この設定はroot所有・第三者書込み不可とし、秘密鍵・パスフレーズを含めない。通常更新では設定をコード所有一覧へ入れず、内容・属性を保持する。更新計画後に設定が変化した場合は処理を保留する。設定欠落・未対応形式・参照先不在を、ホスト名からの推測や既定値への切替えで補わない。

現在の対応形式はformat=1、queue_config_directoryは `/etc/` 配下の通常ディレクトリ、certificate_lineageはCertbotのlineage名である。証明書は同一lineageのlive→archiveリンクを検査し、通常の世代更新を受け入れる。任意の外部証明書ファイルへのリンクは対応対象外である。実行権限は既存監視serviceに従い、権限不足を理由にACLやサービス権限を自動緩和しない。

基本設定とOS・DB・サービス導入adapterを実装した。対象は空のDebian 13 amd64。既存メール構成・同名専用OS利用者・既存DBを検出すると停止する。2026-11-12、専用WSL2内の空Debian 13.5/systemd-nspawnで通常入口からの実導入、実認証UI、署名付き手動/自動更新、故障時復旧と未知差分保留を確認した。検証範囲はVALIDATION.mdを参照する。

## 対応版と配布状況

2026-11-14時点では導入・更新バイナリの配布を停止し、ソースとライセンス資料を公開している。本ページのcheck・reissue・publishは準備中の0.4.0候補の機能である。対応する署名付き導入資材の公開後に本手順を使用する。GitHubの現行mainと旧0.1.1には追加前のコードが含まれる。

新しい初期設定方式は、成功済み工程を再利用した続行と新規差分で確認した。環境チェックのLinux新規12条件、初期UI・仮想パスキー・明示公開・条件付き復旧を確認済み。最新版一式の空OSからの単一無中断実行、実VPSの外部経路、物理認証器は未確認である。

## 導入環境

| 項目 | 準備する内容 |
|---|---|
| OS・CPU | 専用の空Debian 13 amd64/x86_64、systemdをPID1として起動 |
| 管理権限 | rootの対話端末。既存SSHのホスト鍵と接続方法を確認する |
| ツール | DebianのPython 3、dpkg-query、systemctl。kitのbuild・検証用依存はNATIVE_ASSETS.mdを参照 |
| IPv4・名前 | サーバーへ割り当てたグローバルIPv4、メール用FQDN、管理するドメイン |
| TLS・PKI | FQDNと一致する有効なTLS証明書・秘密鍵、新サイト用のCA/issuer資材 |
| ネット接続 | DebianのAPT、公式native資材・定義、公開更新元への必要な接続 |
| 保存先 | rootが管理する書込み可能な配置先と、新規診断領域の既存親フォルダー |
| 容量 | メール・DB・ログ・AV定義・バックアップを収容する容量。固定の最低CPU/RAM/disk必要量は未確定 |

サーバーTLSは事前準備したkit入力とDNS-01取得を選択できる。DNS-01取得・自動更新・各サービスへの反映・CA世代切替えの手順を参照する。[証明書の導入・更新](CERTIFICATES.md)

### 公開ポートと内部ポート

導入開始時は管理用SSHで接続し、VPS側パケットフィルターのメール・Web公開は初期設定と公開判断の後に行う。SSHのポート番号は導入先の現行設定を使用する。

| 外部向けTCP | 用途 |
|---|---|
| 25 | 他メールサーバーからの受信 |
| 443 | Roundcube・管理画面 |
| 465 | 旧SMTP認証ID向けのTLS送信入口 |
| 587 | クライアント証明書方式のメール送信入口 |
| 993・995 | クライアント証明書方式のIMAP・POP接続 |

110・143・3306・4190・6379・10001・10002・10027・11332・11333・11334はloopback等の内部利用として扱う。外部向けポートの許可元と利用範囲は運用に合わせて確定する。公開DNSにはA/PTRと、配送先として採用する時点のMX、送信ドメインのSPF/DKIM/DMARCを準備する。

## 導入前の準備

署名付き正式資材を取得し、別経路で信頼を確認した公開鍵を使って署名とSHA256・サイズを照合する。導入archiveの展開先で作業し、kitは後述のroot専用領域へ配置する。[署名確認手順](../PUBLICATION.md)

site.example.jsonをsite.jsonへコピーし、次の値を導入先に合わせる。例の192.0.2.10は文書用IPv4である。installには実際のグローバルIPv4を指定する。

| キー | 設定する値 |
|---|---|
| mail_host | TLS証明書と一致するメールサーバーのFQDN |
| primary_domain | 最初に管理するメールドメイン |
| public_ipv4 | 導入先のグローバルIPv4 |
| notification_recipient | 管理通知の受信先 |
| legacy_pop_host | 旧POP取込みを使う場合の接続先。初期例はold-disabled.example.invalid |
| legacy_import_email | 移行用アドレス。初期例はlegacy-disabled@example.invalid |
| migration_domain | 移行対象のドメイン |

以下は導入先のrootシェルで実行する。各--evidenceには毎回異なる新規ディレクトリーを指定する。checkの診断先とinstallの診断先も別にする。

## 操作入口

環境チェックを最初に実行する。Debian 13 amd64・systemd、既存の競合アプリとunit、利用予定TCPポート、配置先と親フォルダー、専用ユーザー／グループを一括確認する。検出した競合を一覧で返し、終了値2で停止する。環境チェック本体はホスト設定を変更しない。`--evidence`を指定した場合だけ、新規のroot専用診断領域へ結果を保存する。

```sh
sudo python3 -I -S -B install.py check --site site.json \
  --evidence /root/mail-platform-environment-001
```

配置先の既存資源、途中のsymlink、root以外が所有する親フォルダー、他者の書込み権限、読取り専用ファイルシステムを拒否する。診断保存先がアプリ配置先へ重なる場合も拒否する。専用の空OS向けの導入であり、既存アプリの採用・停止・設定の修復は管理者が判断する。

使用予定ポートはIPv4・IPv6、loopbackを含めて確認する。同じ番号を使用中の別アドレスの待受けも競合として扱う。SSH等の導入対象外ポートの利用は許可する。予約ポートは25/110/143/443/465/587/993/995/3306/4190/6379/10001/10002/10027/11332/11333/11334である。

確認後の状態変化を検出するため、installも初期資格情報の発行前と、設定変更開始前に確認する。保存した診断のPASSで次の実行を無条件に許可する仕組みは設けていない。ネットワーク検査はその時点のTCP待受けを確認するものであり、後から別プロセスが起動する競合やVPS側のパケットフィルターを保証しない。

```sh
python3 -I -S -B install.py plan --site site.json
python3 -I -S -B install.py stage --site site.json --output ./bound-code
python3 -I -S -B install.py prepare --site site.json --facts target-facts.json --output ./private-preparation
```

planは予定工程・package・unit・設定参照を表示する。stageは公開コードを新規領域へ生成する。prepareは0700の新規私有領域へ22設定と新規資格情報を作る。site.example.jsonとfacts.example.jsonは合成例である。prepareの事前検討資材と、installによる新規取引の資格情報は別管理になる。

空OSを用意し、対象・版・停止影響・復旧方法の確認と承認を終えた後の入口を示す。

```sh
sudo python3 -I -S -B install.py install --site site.json \
  --kit /root/mail-platform-kit --evidence /root/mail-platform-install-001 \
  --administrator-email admin@example.test --resolver 1.1.1.1 --apply
```

installは初期管理者用のランダムな期限付きパスワードを生成し、成功後に管理端末だけへ表示する。初期UIは127.0.0.1:443へ限定し、メール関連の公開用unitは停止する。INITIAL_SETUP.mdの初期ログイン・パスキー確認・明示的publishを実施する。installは新規導入用である。中断した場合は取引記録と作成済み資源を照合して続行方法を決定する。

## 初期ログインから公開まで

1. 管理用HTTPS接続経路を用意し、mail_hostと同じホスト名・443で管理画面を開く。
2. 端末に表示された管理者名と30分有効の初期パスワードでログインする。
3. パスキーを登録し、そのパスキーで本人確認を成功させる。
4. rootが次のpublishを実行し、初期値と異なる恒久パスワードを非表示で2回入力する。

```sh
python3 -I -S -B install.py publish --site site.json \
  --confirm-host mx.example.net --evidence /root/mail-platform-publish-001 --apply
```

--confirm-hostにはsite.jsonのmail_hostを指定する。公開処理はメール関連サービスを起動し、nginxを再起動して公開待受けへ切り替える。初期画面の接続は終了する。初期資格情報の再発行、HTTPS接続、公開失敗時の復旧はINITIAL_SETUP.mdに記載した。[初期ログインの詳細](INITIAL_SETUP.md)

公開確認後、ドメイン・利用者、端末証明書、通知・バックアップを設定する。VPS側とOS側のFW規則を確認して必要な入口を許可し、宛先の準備が完了した時点でMXを切り替える。UFWの許可規則とENABLEDは導入先で設定する。

## 現地の私有資材

kit.example.jsonの各files項目に相対pathと実ファイルのSHA256を記載する。kitディレクトリーはroot所有0700、全入力ファイルはroot所有0600・通常ファイル・単一リンクとする。内容は現地の私有領域で管理する。

- tls_certificate / tls_keyは新サーバー名に一致する公開TLS証明書chainと秘密鍵。
- root / issuer / root_crl / custody / restoration / custody_statementは証明書機能の公開CA・CRL・custody/restoration証跡。CA root秘密鍵はオフラインで管理する。新サイト用issuer_keyは暗号化し、issuer_passwordと分けて置く。
- guardは収録C sourceから導入先向けに構築したguard.so。release_public_keyは別経路で信頼を固定したEd25519公開鍵。
- sieve_session_lock / sieve_session_lock_metadataは、同じDovecot build treeから作成したSieve排他moduleとsource/ABI/hash記録である。NATIVE_ASSETS.mdの生成手順と実SHA256を使う。
- github_tokenは配布リポジトリーのRelease取得用資格情報。公開リポジトリーで匿名取得する場合もroot600の入力ファイルを用意し、空値を渡す。実LoadCredentialと厳格なHTTPSで空値の処理を確認した。
- dovecot_packagesに独自修正版1:2.4.1+dfsg1-6+deb13u7+cnfix1の必要7packageを列挙する。dpkg-debで名前・版・amd64/allを照合する。
- clamav_runtime_manifestはfilesオブジェクトを持ち、usr/local以下の各通常ファイルをkit.files内の資材名へ対応させる。ClamAV 1.4.6の署名・ライセンス・依存を確認したruntimeを使用する。definition_main / definition_daily / definition_bytecodeは公式定義である。

例のゼロdigestは実SHA256で置き換える。ClamAV runtime manifestの全memberもkit.filesへ追加する。新サイト用の秘密と資格情報を準備する。

ClamAVの公開runtime資材はnative_assets.pyで組み立てる。NATIVE_ASSETS.mdに公式source/署名、全notice、Dovecot source候補、kit-fragment.jsonの採用手順を記載した。定義DBは導入先FreshClamで取得・検証して3入力へ採用する。公開配布用archiveの定義DB収録数は0である。

## 実行順序

1. root・Debian 13 amd64・空構成・新規証拠領域・kitの属性/hash・排他を照合する。
2. 一時policy-rc.dと常設の公開承認barrierで自動起動を抑止する。候補版を記録し、削除なしのsimulation後、同じ指定版で導入する。Postfix自動構成とRoundcube dbconfig自動作成を抑止する。
3. 専用OS利用者/groupを作り、NSSの実UID/GIDで監査済みguardとunitを変換する。資格情報は新規64桁hexを同じ取引内で使用する。
4. サイト・UID/GID・5証明書actor・private backend・CA参照・22私有設定を組み立てる。Postfix/Dovecot/Rspamd/nginx/FPM、SRS・DKIM・5jailの基本設定を作る。
5. MariaDBの39オブジェクト、最小権限、Roundcube package core＋認証拡張、lock2件・送信量profile2件を作る。DDLごとにstarted/completedを保存する。公開3列のUNION viewにはview SELECTを付与する。
6. コード・設定・unitを原子的に配置して元値と最終hash/属性を保存する。SQLite、POP暗号鍵、DKIM鍵、公式AV資材を初期化し、TLS health unitで公開前bundleを準備する。
7. native構文・TLSの鍵対応/chain/名前・systemd定義を確認し、初期管理者を監査付き取引で登録する。
8. 一時policy-rc.dを元へ戻す。MariaDBとPHP-FPM、loopback HTTPSだけを起動し、公開用unitとtimerは無効化する。
9. DB ping、loopback管理画面HTTPS、公開用unitの停止、公開application listenerが0件であることを確認する。取引・所有コードreceipt・installed版を保存し、隔離初期設定の完了を記録する。全体serviceの起動・自然更新healthは、管理者のpublishで確認する。

## 初期値と現地設定

更新モードはmanual。管理画面でautomaticを選択する実装を収録した。内部通知は現地の宛先/Webhookを設定・確認してから有効化する。AV検査は無効、危険拡張子は空、上流SMTPは直接配送で始める。送信量は既存承認候補値を使用し、画面で変更する。

一般POP取得機能を収録する。旧ken専用・残着回収用の4unitを新規導入から除外する。Roundcubeパスキー用38クラスと認証vendorも組み立てる。

### Roundcubeの互換プラグイン

5つの互換プラグインと共有コードを同梱する。既存オプション、登録名、導入時の既定順、回復URLとデータベースは引き継ぐ。認証世代の照会と回復先の登録・確認で同じ接続実装を使い、ログイン画面のリンクとTurnstileは同じ表示ヘルパーを使う。旧プラグインの現地コピーを用意する工程はない。

引き続き `account_recovery`、`local_ja_tweaks`、`session_epoch_guard` は標準登録に含む。Turnstileと旧回復リンクを有効にする場合は、それぞれサイト用の鍵と旧回復アプリを用意し、Roundcube設定で明示的に有効化する。

ドメイン/利用者登録、初回パスキー登録、MX/SPF/DKIM/DMARC/PTR、公開FW規則、TLS更新元、バックアップ保管/復元確認、通知先は導入先の設定項目である。UFW package/serviceを含むが、許可規則とENABLEDは現地で設定する。backup証拠がない新サイトを旧ホストのbackup成功で代用しない。

## 失敗と復旧

各コマンドの引数、開始/終了時刻、実終了値、timeout、spawn例外/errno、stdout/stderrをroot専用証拠領域へ保存する。SQL/資格情報を含む原文は同領域で管理する。自動再試行は実装していない。

有効化後の失敗はsocketを先に停止し、起動済みserviceと新規常設serviceを停止/無効化する。設定・コードの最終hash/UID/GID/modeが自分の配置と一致する場合だけ復旧する。新規コードは無効名で保持する。未知変更・操作不明はheldを記録する。追加DB・OS利用者・秘密・SQLite・メール・UIDL・履歴を保持する。APT導入/DB作成の削除を復旧に含めない。

## 検証範囲と正式配布の残件

既存mailのUID1001の新規一時領域で、配置/CAS/timeout/実行不能記録、PHP構文、独立MariaDB302工程、基本4サービスの構文を確認した。nginxは合成TLS・loopback18443を使用した。新規ローカルの依存・監視59unit・GitHub空Release・起動/復旧モデルも確認した。

空OSへのAPT/DB/利用者/サービス導入、5証明書actorの実UID/GIDとcapabilityゼロ、ClamAVの非root起動、管理者パスワード/仮想WebAuthn、実systemdによる更新と復旧を確認した。メール/UIDL/履歴は合成データを用い、実台帳・DB設定・資格情報はhashで保持照合した。7日間の合成TLS証明書に対するtls_expiring警告を記録した。実VPSのkernel/boot/FW/公開DNS、実GitHub経由の配信と物理パスキーは導入先で確認する。本番署名鍵は準備済みである。

更新候補を作る場合はbuild.pyへ--update-contractを渡す。update-contract.example.jsonの版と対象unitを、そのReleaseの差分に合わせて設定する。新規導入が保存するformat 2のinstalled-code.jsonを使用し、既存所有物だけをCASで更新・復旧する。データ・資格情報・メール・UIDL・履歴の削除は含めない。schema/設定blueprintや証明書runtimeが変わるReleaseは専用migration hookで扱う。

参照資料は [Dovecot SQL](https://doc.dovecot.org/2.4.1/core/config/auth/databases/sql.html)、[Postfix MySQL](https://www.postfix.org/MYSQL_README.html)、[Debian Postfix templates](https://sources.debian.org/src/postfix/3.11.7-1/debian/templates)、[MariaDB InnoDB設定](https://mariadb.com/docs/server/server-usage/storage-engines/innodb/innodb-system-variables)である。
