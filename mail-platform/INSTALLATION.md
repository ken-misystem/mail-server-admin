# Debian 13新規導入候補

基本設定とOS・DB・サービス導入adapterを実装した。対象は空のDebian 13 amd64。既存メール構成・同名専用OS利用者・既存DBを検出すると停止する。2026-11-12、専用WSL2内の空Debian 13.5/systemd-nspawnで通常入口からの実導入、実認証UI、署名付き手動/自動更新、故障時復旧と未知差分保留を確認した。検証範囲はVALIDATION.mdを参照する。

## 操作入口

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

管理者の新しいパスワードを端末の非表示入力で2回受け付ける。installは新規導入用である。中断した場合は取引記録と作成済み資源を照合して続行方法を決定する。

## 現地の私有資材

kit.example.jsonの各files項目に相対pathと実ファイルのSHA256を記載する。kitディレクトリーはroot所有0700、全入力ファイルはroot所有0600・通常ファイル・単一リンクとする。内容は現地の私有領域で管理する。

- tls_certificate / tls_keyは新サーバー名に一致する公開TLS証明書chainと秘密鍵。
- root / issuer / root_crl / custody / restoration / custody_statementは証明書機能の公開CA・CRL・custody/restoration証跡。CA root秘密鍵はオフラインで管理する。新サイト用issuer_keyは暗号化し、issuer_passwordと分けて置く。
- guardは収録C sourceから導入先向けに構築したguard.so。release_public_keyは別経路で信頼を固定したEd25519公開鍵。
- github_tokenは配布リポジトリーのRelease取得用資格情報。公開リポジトリーで匿名取得する場合もroot600の入力ファイルを用意し、空値を渡す。実LoadCredentialと厳格なHTTPSで空値の処理を確認した。
- dovecot_packagesに独自修正版1:2.4.1+dfsg1-6+deb13u7+cnfix1の必要7packageを列挙する。dpkg-debで名前・版・amd64/allを照合する。
- clamav_runtime_manifestはfilesオブジェクトを持ち、usr/local以下の各通常ファイルをkit.files内の資材名へ対応させる。ClamAV 1.4.6の署名・ライセンス・依存を確認したruntimeを使用する。definition_main / definition_daily / definition_bytecodeは公式定義である。

例のゼロdigestは実SHA256で置き換える。ClamAV runtime manifestの全memberもkit.filesへ追加する。新サイト用の秘密と資格情報を準備する。

ClamAVの公開runtime資材はnative_assets.pyで組み立てる。NATIVE_ASSETS.mdに公式source/署名、全notice、Dovecot source候補、kit-fragment.jsonの採用手順を記載した。定義DBは導入先FreshClamで取得・検証して3入力へ採用する。公開配布用archiveの定義DB収録数は0である。

## 実行順序

1. root・Debian 13 amd64・空構成・新規証拠領域・kitの属性/hash・排他を照合する。
2. 一時policy-rc.dでAPTの自動起動を抑止する。候補版を記録し、削除なしのsimulation後、同じ指定版で導入する。Postfix自動構成とRoundcube dbconfig自動作成を抑止する。
3. 専用OS利用者/groupを作り、NSSの実UID/GIDで監査済みguardとunitを変換する。資格情報は新規64桁hexを同じ取引内で使用する。
4. サイト・UID/GID・5証明書actor・private backend・CA参照・22私有設定を組み立てる。Postfix/Dovecot/Rspamd/nginx/FPM、SRS・DKIM・5jailの基本設定を作る。
5. MariaDBの39オブジェクト、最小権限、Roundcube package core＋認証拡張、lock2件・送信量profile2件を作る。DDLごとにstarted/completedを保存する。公開3列のUNION viewにはview SELECTを付与する。
6. コード・設定・unitを原子的に配置して元値と最終hash/属性を保存する。SQLite、POP暗号鍵、DKIM鍵、公式AV資材を初期化し、TLS health unitで公開前bundleを準備する。
7. native構文・TLSの鍵対応/chain/名前・systemd定義を確認し、初期管理者を監査付き取引で登録する。
8. 一時policy-rc.dを元へ戻す。socket、互換認証、基礎サービス、証明書target、ログcollector、publisher、容量collector、AV、socket worker、timerを順に起動し、自動起動を設定する。
9. 必須service・DB ping・自分の管理画面HTTPS・後続publisher世代を確認する。取引・所有コードreceipt・installed版を保存し、読戻してcompleteを記録する。

## 初期値と現地設定

更新モードはmanual。管理画面でautomaticを選択する実装を収録した。内部通知は現地の宛先/Webhookを設定・確認してから有効化する。AV検査は無効、危険拡張子は空、上流SMTPは直接配送で始める。送信量は既存承認候補値を使用し、画面で変更する。

一般POP取得機能を収録する。旧ken専用・残着回収用の4unitを新規導入から除外する。Roundcubeパスキー用38クラスと認証vendorも組み立てる。Turnstileと旧standalone recoveryリンクのpluginは初期一覧から除外した。前者には現地keys、後者には別recoveryアプリが必要である。account_recoveryは初期一覧に含む。

ドメイン/利用者登録、初回パスキー登録、MX/SPF/DKIM/DMARC/PTR、公開FW規則、TLS更新元、バックアップ保管/復元確認、通知先は導入先の設定項目である。UFW package/serviceを含むが、許可規則とENABLEDは現地で設定する。backup証拠がない新サイトを旧ホストのbackup成功で代用しない。

## 失敗と復旧

各コマンドの引数、開始/終了時刻、実終了値、timeout、spawn例外/errno、stdout/stderrをroot専用証拠領域へ保存する。SQL/資格情報を含む原文は同領域で管理する。自動再試行は実装していない。

有効化後の失敗はsocketを先に停止し、起動済みserviceと新規常設serviceを停止/無効化する。設定・コードの最終hash/UID/GID/modeが自分の配置と一致する場合だけ復旧する。新規コードは無効名で保持する。未知変更・操作不明はheldを記録する。追加DB・OS利用者・秘密・SQLite・メール・UIDL・履歴を保持する。APT導入/DB作成の削除を復旧に含めない。

## 検証範囲と正式配布の残件

既存mailのUID1001の新規一時領域で、配置/CAS/timeout/実行不能記録、PHP構文、独立MariaDB302工程、基本4サービスの構文を確認した。nginxは合成TLS・loopback18443を使用した。新規ローカルの依存・監視59unit・GitHub空Release・起動/復旧モデルも確認した。

空OSへのAPT/DB/利用者/サービス導入、5証明書actorの実UID/GIDとcapabilityゼロ、ClamAVの非root起動、管理者パスワード/仮想WebAuthn、実systemdによる更新と復旧を確認した。メール/UIDL/履歴は合成データを用い、実台帳・DB設定・資格情報はhashで保持照合した。7日間の合成TLS証明書に対するtls_expiring警告を記録した。実VPSのkernel/boot/FW/公開DNS、実GitHub経由の配信と物理パスキーは導入先で確認する。本番署名鍵は準備済みである。

更新候補を作る場合はbuild.pyへ--update-contractを渡す。update-contract.example.jsonの版と対象unitを、そのReleaseの差分に合わせて設定する。新規導入が保存するformat 2のinstalled-code.jsonを使用し、既存所有物だけをCASで更新・復旧する。データ・資格情報・メール・UIDL・履歴の削除は含めない。schema/設定blueprintや証明書runtimeが変わるReleaseは専用migration hookで扱う。

参照資料は [Dovecot SQL](https://doc.dovecot.org/2.4.1/core/config/auth/databases/sql.html)、[Postfix MySQL](https://www.postfix.org/MYSQL_README.html)、[Debian Postfix templates](https://sources.debian.org/src/postfix/3.11.7-1/debian/templates)、[MariaDB InnoDB設定](https://mariadb.com/docs/server/server-usage/storage-engines/innodb/innodb-system-variables)である。
