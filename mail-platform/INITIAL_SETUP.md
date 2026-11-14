# 公開前の初期ログイン

本ページは準備中の0.4.0候補に対応する。導入・更新バイナリは配布停止中であり、対応する署名付き資材の公開後に使用する。

新規導入は外部向けのメール受付を停止した状態で完了する。初期UIのHTTPSは127.0.0.1:443で待ち受ける。初期管理者のパスキー登録・確認と、恒久パスワードへの切替えを終え、サーバー管理者がpublishを実行してから公開する。

導入の先頭ではINSTALLATION.mdの環境チェックを実行する。installの通常入口にも同じ確認を組み込み、競合時は初期資格情報の発行とホスト設定変更へ進まない。

## 初期資格情報の発行

installは対話端末を必要とする。32byteの暗号学的乱数から初期パスワードを生成し、導入成功後に/dev/ttyへ管理者名・URL・初期パスワードを表示する。標準出力のJSON、コマンド引数、取引ログ、配布資材へ平文を保存しない。管理者DBには既存のpassword encoderによるhashを保存する。

初期パスワードの有効期限は発行から30分である。期限切れ、時計の巻戻し、本人・認証世代・password fingerprintの不一致はログインを拒否する。固定の初期パスワードや、公開画面から最初の管理者を作る入口は設けない。

期限切れや表示を失った場合は、サーバー管理者が次を実行する。既存の管理者1件を使い、パスワードと認証世代を更新する。元の資格情報と古いsessionは失効する。既存のパスキーは保持する。

```sh
sudo python3 -I -S -B install.py reissue --site site.json \
  --evidence /root/mail-setup-reissue-001 --apply
```

## UIへ接続する

サーバーの既存SSH接続を使い、利用者のPCだけにloopback forwardを設定する。SSHのホスト鍵を確認し、サーバーのsshd設定・認証方式・FWを緩和しない。これは導入先管理者による接続例である。

```sh
ssh -N -a -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:443:127.0.0.1:443 administrator@server-address
```

PC側で実際のメールホスト名が127.0.0.1へ解決されるよう、初期設定用の名前解決を用意する。ブラウザーではsite.jsonとTLS証明書に指定した同じホスト名を使う。例は`https://mx.example.test/mail-admin/login`である。localhostへのURL置換やportの変更は、WebAuthnのorigin/RP設定と一致しない。TLS証明書の検証を無効にしない。TLSはDNS検証等で事前準備したkitの証明書を使う。

表示された管理者名と初期パスワードでログインし、パスキーを登録した後、パスキーによる本人確認を成功させる。初期画面の接続はサーバーloopbackのままである。

## 明示的に公開する

```sh
sudo python3 -I -S -B install.py publish --site site.json \
  --confirm-host mx.example.test --evidence /root/mail-publish-001 --apply
```

操作にはrootと、対象ホスト名の一致を必要とする。有効なパスキーに実認証の記録があることをSQL取引で確認する。初期パスワードと異なる恒久パスワードを非表示で2回入力する。パスワード更新と認証世代更新をcommitし、初期資格情報を失効させる。その後、公開承認barrier、メール関連service/socket/timer、公開HTTPSを有効化し、既存の全体healthと自然更新を確認する。loopbackから公開待受けへの切替えではnginxを再起動するため、初期設定画面の接続は終了する。

公開の失敗後も完了済みの恒久パスワードと認証世代は保持する。続行時はその資格情報を照合して再利用し、再入力と再変更は行わない。

VPS側のパケットフィルター、OSの許可規則、DNSは管理者が別途確認する。publishはVPSパネルやDNSを変更しない。

## 中断・再起動

APT中の自動起動はpolicy-rc.dで抑止する。公開用unitには常設のRequires/After barrierを設定し、未公開状態の手動startと再起動時の自動startを拒否する。初期UIにも別の承認barrierを設ける。nginxの既定公開siteと追加server snippetのincludeを外し、初期UIの単一設定だけを読み込む。

初期導入失敗時は公開barrierを閉じ、既知の設定だけを条件付き復旧する。安全なbarrierは保持する。公開中の状態はboot IDに対応付け、未完了の公開を次回bootへ引き継がない。公開処理の失敗では公開barrierとUIを停止し、既知の設定復旧後に隔離UIを戻す。未知差分・結果不明は保留し、DB・メール・UIDL・資格情報・履歴を保持する。

既存導入先に初期アクセスmetadataがない場合、通常の管理者認証を継続する。新規導入の公開承認は更新処理から自動作成しない。

## 参照資料

- OpenSSHのlocal forwardを使う。[OpenSSHマニュアル](https://man.openbsd.org/ssh#L)
- 初期秘密値は暗号学的乱数・期限・安全な伝達経路で扱う。[OWASPのtoken取扱い](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
