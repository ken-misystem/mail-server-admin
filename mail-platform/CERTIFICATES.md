# 証明書の導入・更新

本ページは準備中の0.4.0候補に対応する。導入・更新バイナリは配布停止中であり、対応する署名付き資材の公開後に使用する。

## 対象と実装状況

| 証明書 | 導入する人・用途 | 導入・更新の状況 |
|---|---|---|
| サーバー用TLS | 管理者。Web・SMTP・IMAP・POPでサーバーを確認する | 事前に用意した証明書と鍵をkitから配置する。更新元ファイルの変更検出・gateへの反映・期限監視を実装済み。ACME取得・更新設定と全利用サービスへの反映は残件 |
| 端末用クライアント証明書 | 利用者。587・993・995への本人確認 | Roundcubeで端末ごとに発行し、P12をメールアプリへ取り込む。期限前に新しい証明書を発行・設定し、旧証明書を失効する |
| root CA・issuer CA | 管理者。端末証明書の信頼元・署名元 | 新サイトの資材を事前準備してkitへ入力する。期限監視を実装済み。CA世代交代の導入先向け自動移行は残件 |

## サーバー用TLSの初回導入

1. site.jsonのmail_hostを確定し、そのFQDNに一致する証明書chainと秘密鍵を用意する。
2. 初期の外部ポートを閉じた状態で発行する場合は、DNS-01でDNS所有権を確認する方法を使用できる。HTTP-01は80番への到達を必要とする。[Let's Encrypt公式の認証方式](https://letsencrypt.org/docs/challenge-types/)
3. 現行installerのTLS配置先は新規作成を前提とする。初回資材は別の安全な作業環境で取得し、導入先の私有kitへ転送する。導入先で先に同じFQDNのCertbot lineageを作成すると、環境チェックまたはTLS_live_source_existsで停止する。
4. kit.jsonのtls_certificateへPEMのfull chain、tls_keyへ対応するPEM秘密鍵を登録し、実ファイルのSHA256を指定する。TLSサービス用の秘密鍵は無人読込みに対応する形式を使用する。root所有・file0600・kit directory0700で保管する。
5. installerがchain・ホスト名・鍵対応を検査した後、次の配置を作成する。これらはkitから採用した入力である。

```text
/etc/letsencrypt/archive/<mail_host>/fullchain1.pem
/etc/letsencrypt/archive/<mail_host>/privkey1.pem
/etc/letsencrypt/live/<mail_host>/fullchain.pem -> ../../archive/<mail_host>/fullchain1.pem
/etc/letsencrypt/live/<mail_host>/privkey.pem   -> ../../archive/<mail_host>/privkey1.pem
```

この配置に加え、ACMEを使う運用ではアカウント・DNS認証・更新設定の導入が必要である。現在のinstallerは証明書と鍵の配置までを行う。CertbotのACMEアカウントやrenewal設定の作成・既存lineageの採用は残件である。

初期UIもTLSを使用する。管理用HTTPS接続ではmail_hostと同じホスト名・443を使用し、ブラウザーで証明書chainと名前を確認する。[初期ログイン](INITIAL_SETUP.md)

## サーバー用TLSの更新

### 実装済みの反映と監視

mail-client-cert-health.timerは起動から5分後、その後は前回処理終了から5分ごとに確認する。次の処理を行う。

1. 設定されたliveのリンク先をarchive配下で解決し、root所有・権限・ファイル安定性を確認する。
2. 新しい証明書の有効期間・mail_host・鍵対応を確認する。
3. 検査済みの証明書と鍵から新しいTLS bundleを作成し、currentを原子的に切り替える。
4. 公開後に証明書が変わった場合、mail-client-cert-gate.serviceをtry-restartし、gateが提示する証明書hashを照合する。世代ごとの再起動intentを保存し、同じ世代の不明な再実行を拒否する。

gateの再起動を伴う。587・993・995の継続接続を維持した証明書更新は未確認である。

監視の期限警告はサーバーTLSが残り21日、issuer CAが30日、root CAが180日、CRLが8時間である。期限切れと反映後のhash不一致も検出する。監視・bundle反映の実装はhealth.py、周期はsystemd timerで確認できる。[TLS監視の実装](payload/usr/local/lib/mail-client-cert-public-v1/health.py)、[timer](payload/blueprint/systemd/mail-client-cert-health.timer)

### 導入先の更新経路として残る作業

| 工程 | 現在の状態 |
|---|---|
| ACME初回発行・DNS API認証 | 導入先のDNS事業者・認証方法に合わせた設定が必要 |
| ACME更新timer・認証情報保管 | パッケージの初回導入への組込みは残件 |
| Certbot管理lineageの採用 | installerが作成する配置との整合・所有関係の移行が残件 |
| 更新後のnginx・Postfix等への反映 | 各利用サービスの構文検証・reload・提示証明書確認を含む共通deploy hookが残件 |
| 証明書と鍵の更新中の整合 | liveの切替えとhealth実行の協調を含む一連の新規検証が必要 |

ACMEを導入する運用では、更新成功後のdeploy hookと更新試験を設定する。Certbotのmanual方式を使う自動更新には認証hook等の構成が必要である。[Certbot公式の更新手順](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates)

nginx・Postfix・Dovecotとgateの反映が完了したことは、それぞれの新しい接続で提示される証明書を確認して判定する。ファイルの更新時刻やtimerの起動だけで全入口の更新完了と判定しない。

### 管理者の読取り確認

次は導入先で現在の期限・監視状態を確認する読取りコマンドである。mx.example.netをmail_hostへ置き換える。

```sh
openssl x509 -in /etc/letsencrypt/live/mx.example.net/fullchain.pem \
  -noout -subject -issuer -dates -ext subjectAltName
systemctl list-timers --all mail-client-cert-health.timer
systemctl status mail-client-cert-health.service --no-pager
journalctl -u mail-client-cert-health.service -n 30 --no-pager
```

## 端末用クライアント証明書

### 新しいメールアプリへ導入する

1. Roundcubeへログインし、「設定」からパスキーを登録する。
2. 「アプリ用パスワード」で端末ごとの認証情報を発行して保存する。
3. 「端末証明書」で本人のアカウント・端末名を確認し、P12保護パスワードを設定して発行する。保護パスワードは空白を含まない半角英数記号16〜128文字とする。
4. 同じ発行画面で、表示された期限内にP12を1回取得する。取得期限は最大5分である。未取得のまま期限が過ぎた証明書は自動無効化の対象となる。
5. 対応するメールアプリへP12を取り込み、受信と送信の両方へ本人の証明書を指定する。ユーザー名とアプリ用パスワードも設定する。
6. Roundcubeの「メールアプリ登録方法」のアプリ別図解に沿って接続を確認する。

P12には端末の秘密鍵が含まれる。P12保護パスワードは取込み時に使用し、メール送受信の認証にはアプリ用パスワードを使用する。端末を追加するときは新しい端末用証明書を発行する。

### 期限前の入替えと紛失時の対応

現在の端末証明書policyは90日である。画面に表示される個別の有効期限と発行上限を確認し、期限前に新しい証明書を発行する。新しいP12を端末へ取り込み、受信・送信双方の証明書選択と新しい接続を確認してから旧証明書を無効化する。

この入替えは利用者のP12取込み操作を伴う。既存P12の有効期限を自動で延長する処理や、端末の証明書保管庫を自動で書き換える処理は実装していない。

端末紛失・鍵漏えい時は、対象の端末証明書とアプリ用パスワードを無効化する。本人確認を経て新しい端末用資材を発行する。旧証明書を復活させる復旧は行わない。

発行・無効化の画面と取得条件はRoundcube pluginの実装で確認できる。[端末証明書画面](payload/usr/share/roundcube/plugins/mail_client_certificates/skins/elastic/templates/certificates.html)

## CAと失効情報の管理

root CA秘密鍵はオフラインで保管する。暗号化したissuer秘密鍵とその保護情報、公開CA証明書・CRL、保管・復旧確認の証跡を新サイトのkitへ用意する。issuerの実行資格情報はLoadCredentialで渡す。

失効情報はissuerがCRLを発行し、gateが更新・検証する。CRLの有効期限が切れた接続は拒否する。CRLの定期更新とCAの世代交代はそれぞれの工程として扱う。

root CA・issuer CAの期限前には、新しい署名元・信頼chain・既存端末の扱い・失効情報・切替えと復旧を計画する。CA世代交代を一括実行する導入先向けランチャーは残件である。既存CA・issuer・台帳を毎回生成し直す更新手順は採用しない。

## 現在の完了判定

クライアント証明書の発行・失効、P12の取得と取込み手順、TLS変更検出・gate反映・期限監視の実装を確認した。サーバーTLSのACME取得から全入口への更新反映、CA世代交代までを含む初回導入・自動更新は残件である。正式資材の再公開判断では、この残件も確認する。
