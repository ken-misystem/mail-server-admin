# 証明書の導入・自動更新・CA切替え

準備中の0.4.0候補に対応する。配布資材の再公開は承認待ちである。

## サーバー用TLS

DNS-01による初回取得・自動更新を実装した。CloudflareとRFC2136を設定で選択する。専用Certbot領域は `/var/lib/mail-platform-acme`、アプリへの公開先は `/etc/letsencrypt/live/<mail_host>` である。

初回取得にはDNS編集権限と外向き通信を使う。Web・メールの受信ポートを閉じた状態で実行できる。FQDNに一致する証明書を用意する。DNS資格情報はroot所有0600、親ディレクトリーはroot管理とする。

### 初回取得

1. site.jsonとroot専用kitを準備する。TLS未登録の場合はkit.example.jsonのTLS用ゼロhashを保持し、該当入力ファイルを作成しない。
2. acme.example.jsonをroot専用ファイルへコピーし、ホスト名・連絡先・DNS方式・資格情報のパスを設定する。
3. ACME事業者の利用条件を確認した管理者がterms_agreedをtrueに設定する。
4. 次を導入archiveの展開先で実行する。各診断先には新しいディレクトリーを指定する。

```sh
sudo python3 -I -S -B install.py check --site site.json \
  --evidence /root/mail-check-001
sudo python3 -I -S -B install.py acme-bootstrap --site site.json \
  --kit /root/mail-platform-kit --acme-config /root/mail-acme.json \
  --evidence /root/mail-acme-bootstrap-001 --apply
sudo python3 -I -S -B install.py install --site site.json \
  --kit /root/mail-platform-kit --acme-config /root/mail-acme.json \
  --administrator-email admin@example.net \
  --evidence /root/mail-install-001 --apply
```

acme-bootstrapは環境チェックを最初に行い、Certbotと選択したDNS pluginを導入し、取得結果とSHA256をkitへ登録する。既存TLS入力の上書きを拒否する。installは環境チェックを再度実行し、初期UIをloopbackへ配置する。初期ログイン・パスキー・公開操作は初期設定手順に従う。[初期設定](INITIAL_SETUP.md)

既に `/etc/letsencrypt/renewal/<mail_host>.conf` を持つ構成は競合として停止する。既存Certbot lineageの自動移管は対象外である。

### DNS資格情報

Cloudflareは対象zoneへ限定したDNS編集tokenをroot専用INIのdns_cloudflare_api_tokenへ設定する。RFC2136はdns_rfc2136_server、dns_rfc2136_port、dns_rfc2136_name、dns_rfc2136_secret、dns_rfc2136_algorithmを設定する。TSIG更新権限を対象の_acme-challenge TXTへ限定する。

資格情報の形式・必要権限を公式資料で確認する。資格情報をGitへ登録しない。[Cloudflare plugin](https://certbot-dns-cloudflare.readthedocs.io/en/stable/)、[RFC2136 plugin](https://certbot-dns-rfc2136.readthedocs.io/en/stable/)

### 登録と周期

初回導入の--acme-configで登録できる。後から登録する場合は次を実行する。Certbotと選択したDNS pluginの導入が前提となる。

```sh
sudo python3 -I -S -B /usr/local/lib/mail-platform-update/certificate_cli.py \
  acme-configure --configuration /root/mail-acme.json \
  --evidence /root/mail-acme-register-001 --apply
systemctl list-timers --all mail-platform-acme.timer
journalctl -u mail-platform-acme.service -n 30 --no-pager
```

timerは起動15分後、前回終了から12時間ごとに起動し、最大1時間の分散待ちを加える。更新要否はCertbotが判定する。LoadCredentialで資格情報を渡す。更新workerはcapability全項目0・NoNewPrivileges・swap0で実行する。

### 反映と障害

chain・ホスト名・鍵対応・有効期間を検査し、証明書と鍵を同じ不変世代へ配置する。liveとgate用bundleの切替えを記録し、nginx・Postfix・Dovecotをreload、gateを再起動する。25・443・465・587・993・995の新しい接続で提示証明書を確認する。初期設定中はloopback443だけを更新する。

gate再起動により587・993・995の継続接続には再接続が必要となる。reload後の収束を最大20秒観測する。

通常の失敗は参照先が自分の変更と一致する場合だけ復旧する。強制終了で未確定記録が残った場合は次の更新を停止する。管理者が記録を確認して反映完了または復旧を選択する。

```sh
sudo python3 -I -S -B /usr/local/lib/mail-platform-update/certificate_cli.py \
  tls-recover --evidence /root/mail-tls-recover-001 --apply
sudo python3 -I -S -B /usr/local/lib/mail-platform-update/certificate_cli.py \
  tls-recover --rollback --evidence /root/mail-tls-rollback-001 --apply
```

未知差分では保留する。世代・鍵・失敗記録を保持する。root専用状態は/var/lib/mail-platform-certificatesへ保存する。外部取得した証明書にはtls-deploy --certificate <chain> --key <key> --evidence <新規root領域> --applyを使用できる。

## 端末用証明書

利用者はRoundcubeの「端末証明書」から端末ごとにP12を発行する。メールアプリへP12とアプリ用パスワードを設定する。期限前に新しい証明書へ更新し、旧証明書を失効する。アプリ別の手順はRoundcubeの「メールアプリ登録方法」に掲載する。

## CAの世代切替え

root秘密鍵をオフラインで管理する。新世代の入力は次の8ファイルに限定する。root秘密鍵の入力と、同じCRL署名者の別論理世代登録を拒否する。

```text
root  issuer  root_crl  custody  restoration  custody_statement
issuer_key  issuer_password
```

現在世代と最大2件の旧世代を同時に信頼する。各issuerのCRL署名と単調増加カウンターを維持する。公開済みシステムで実行する。有効な未取得P12が残る場合は停止する。

```sh
sudo python3 -I -S -B /usr/local/lib/mail-platform-update/certificate_cli.py \
  ca-prepare --directory /root/new-ca --apply
sudo python3 -I -S -B /usr/local/lib/mail-platform-update/certificate_cli.py \
  ca-activate --issuer-id <新UUID> --evidence /root/mail-ca-001 --apply
sudo python3 -I -S -B /usr/local/lib/mail-platform-update/certificate_cli.py \
  ca-rollback --issuer-id <旧UUID> --evidence /root/mail-ca-back-001 --apply
sudo python3 -I -S -B /usr/local/lib/mail-platform-update/certificate_cli.py \
  ca-retire --issuer-id <旧UUID> --evidence /root/mail-ca-retire-001 --apply
```

ownerとgate/socket・issuerを停止して資格情報と公開chainを切り替え、gate観測後にownerを再開する。切替え中はクライアントの再接続が必要となる。

戻し操作でも他世代の信頼を保持する。旧CA廃止は端末表とissuer台帳の双方で有効期限を確認し、未期限切れ0件の場合に許可する。DB履歴・暗号化issuer資材を保持する。

途中停止はca-recover --evidence <新規root領域> --applyで処理を完了する。ca-recover --rollbackは発行再開要求前に限定する。再開要求後は全CAの資材と信頼を保持して確認する。未知差分は保留する。

## 既存版への組込み

署名対象のcertificates-v1 descriptorで専用移行hookを選択する。導入receipt・全コードhash・actor設定・gateのmount・静的登録を照合してstageする。未知のコード・drop-in・新規パスの衝突は変更前に停止する。

初回のruntime変更ではowner・gate/socket・issuer等を停止し、有効な未取得P12が0件であることを確認する。新しいruntime manifestとactor設定をCAS反映し、実起動とgateの正常性を確認する。新しいACME unitは配置だけを行い、登録操作でtimerを開始する。

gate専用の登録済みruntime viewは全pinとunitを照合し、backend front設定を保持して共通runtimeへ統合する。元viewは保持する。証明書runtimeが同一の後続更新ではgateの停止を要求しない。

format 2では静的移行の後に登録済みアプリの世代を切り替える。故障時はアプリ世代、証明書移行の順に既知差分を復旧する。移行中断記録が残った場合、ACME・TLS・CA操作を停止する。署名済み展開先のinstaller.py rollback --transaction <対象transaction>で既知journalを復旧する。結果不明のサービス操作と未知差分は管理者による確認が必要となる。

## 検証範囲

隔離Debian13で85条件を確認した。実Certbot・Pebble・TSIG DNS、実nginx/Postfix/Dovecot/gate、旧新CAのTLS・失効RPC、強制終了復旧、初期UI更新、既存版移行、format 2結合、実保護unitを含む。初回導入・入力・移行ガードはローカル28条件と旧版接続モデル5条件で補完した。

実Let's Encrypt・Cloudflare外部APIと実VPS経路は未確認である。最新版一式は、新しいDebian13検証像で通常CLIの導入・初期UIログイン・仮想パスキー登録・明示公開・自然更新まで連続実行した。合成kitとキャッシュを再利用し、実メールは送信していない。

実0.3.0の保存journalから復元した別の検証像で、署名検証・Sieve/証明書移行・正常性確認まで連続実行した。同じ候補のhealth後故障では、更新器が0.3.0へ自動復旧し、Maildir・UIDL・UIDVALIDITY・DB・台帳・資格情報が一致した。従来の個別機能試験は保存証拠を再利用した。未移行runtimeを検出したCA操作は変更前に停止する。

二層の復旧では、各層が記録したowner/gateの再起動結果を実値照合して引き継ぐ。復旧済み層の続行時はファイルとunitを確認し、再起動を繰り返さない。元は停止中だったunitが連動停止で同じ停止状態へ戻った場合も記録する。未知のPIDやファイル変更は拒否する。
