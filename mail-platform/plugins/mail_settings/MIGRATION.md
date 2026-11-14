# 設定プラグインへの移行と復旧

対象OSはDebian 13。本人が承認した固定hashのpayloadと、root専用の証拠領域を使う。

## 準備するもの

- plugin modeで生成したpayloadと、そのsize／SHA256の確認結果。
- 現行のRoundcube config、managesieveのengine／forward、Web側pluginリンクのhash／属性。
- PHP実行UID/GIDが33であることと、TLS証明書の照合名。
- 既存の個人Sieve、標準managesieve以外のwriter、保存世代の容量運用。

DebianのWeb側pluginパスは/var/lib/roundcube/pluginsである。コードは/usr/share/roundcube/pluginsへ配置し、root所有のリンクで登録する。新規installerはsource-catalogに含む独自pluginを登録し、そのreceiptを保存する。未知の既存ディレクトリや別targetのリンクでは停止する。

## CLI

候補payload内のusr/local/lib/mail-platform-update/roundcube_migration.pyを実行する。以下のパスは適用時に固定する。

```sh
python3 -B /root/approved-payload/usr/local/lib/mail-platform-update/roundcube_migration.py prepare \
  --root / --payload /root/approved-payload \
  --evidence /root/approved-roundcube-settings-migration --peer mx.example.net
```

prepareは構文確認と、元属性・配置候補の保存を行う。configの値を含むstage／backupはroot専用領域で保管する。PCやGitHubへ返す資料はhash・属性・状態だけにする。

本番反映の承認後、PHP-FPMを停止して既存workerの終了を確認する。Roundcubeと同じFPMを使う管理画面も一時的に利用できなくなる。SMTP／IMAP／POPのサービス操作はこの移行CLIに含まれない。

```sh
python3 -B /root/approved-payload/usr/local/lib/mail-platform-update/roundcube_migration.py activate \
  --root / --evidence /root/approved-roundcube-settings-migration
```

activateはPHP-FPMまたはUID33のPHP workerが稼働していれば拒否する。元hashと属性、stage、Webリンクを再照合し、プラグイン配置・既知2修正の逆適用・設定変更を行う。最新のconfigを退避し、原子的な配置と読戻しを行う。既存メール・UIDL・個人Sieve・DB行を操作しない。

公開前にmark-publishedを記録し、PHP-FPMを再開して新画面と監視を確認する。

```sh
python3 -B /root/approved-payload/usr/local/lib/mail-platform-update/roundcube_migration.py mark-published \
  --root / --evidence /root/approved-roundcube-settings-migration
```

## 復旧

公開前の失敗は、PHP worker終了後にrestoreを実行する。自分が配置したhash・属性と一致するファイル／リンクだけを復旧する。新規コードは既存のFile transactionと同じ方法で非稼働名へ保持する。新規のlock領域を保持する。

```sh
python3 -B /root/approved-payload/usr/local/lib/mail-platform-update/roundcube_migration.py restore \
  --root / --evidence /root/approved-roundcube-settings-migration
```

mark-published後はrestoreを保留し、現在のコード・configと利用者設定を保持する。公開後の利用者変更と旧UIの対応を確認して復旧方針を決める。未知の差異も保留する。

## 更新機構との接続

component CLIはconfig・コード・リンクを扱う。更新器へ登録済みの環境では、roundcube_rollout.pyがreceipt採用とWeb終了／再開をまとめる。対象はDebian 13の標準php8.4-fpm.serviceを直接使う構成である。世代別Webを稼働させた環境は、routeとsnapshotの移行工程へ引き継ぐため変更前に停止する。

旧導入に使用したblueprint/install-recipes.jsonを用意する。現在の所有receiptに記録したsiteへbindしたhashが一致することを要求する。新recipeはmanagesieveからmail_settingsへの置換とmail_settings_enabled=trueだけを許可し、その他のblueprint・schema・unit・版・site・identityを保持する。配置したplugin・helper・policyと既知core修正の所有metadataを同じreceiptへ採用する。通常の更新処理が使用するrender入口との接続を隔離確認した。

```sh
python3 -I -S -B /root/approved-payload/usr/local/lib/mail-platform-update/roundcube_rollout.py prepare \
  --root / --payload /root/approved-payload \
  --previous-recipe /root/approved-previous-recipes.json \
  --evidence /root/approved-mail-settings-rollout \
  --hostname mail.example.net --peer mx.example.net
```

prepareはroot専用の候補・退避予定とplan.jsonを作成し、planのSHA256を返す。nginx -Tの原文とPHP設定を含む出力はroot専用領域へ保存する。公開資料へ返す項目はhash・属性・有限の状態に限定する。適用直前に具体的なhostname・plan hash・配布hash・停止対象を本人へ提示する。

```sh
python3 -I -S -B /root/approved-payload/usr/local/lib/mail-platform-update/roundcube_rollout.py apply \
  --root / --evidence /root/approved-mail-settings-rollout \
  --apply --plan-sha256 APPROVED_PLAN_SHA256
```

適用は既存更新器のupdate.lockを取得する。元の更新timerがactiveの場合だけ一時停止し、nginxへSIGQUITを送り、既存Web要求の完了とFastCGI接続0を待つ。その後PHP-FPMへSIGQUITを送り、終了を確認して配置・receipt採用・構文確認を行う。PHP-FPMとFastCGI健康確認、nginxの順に再開し、保護6サービスの状態／PID／InvocationID・配置hashを照合して元timerを戻す。Web終了の待機上限は60秒。nginxのworker_shutdown_timeoutが65秒未満の有限値なら準備を拒否する。時間切れで強制終了を追加しない。

nginx停止中、Roundcubeと同じnginxを使う管理画面等の新規Web接続が一時的に利用できなくなる。SMTP・IMAP・POP・DB・Rspamdへの制御コマンドは含まれない。正常な処理中HTTP要求が完了することを実nginx／PHP-FPM unitで確認した。

公開前の確定した失敗は、コード・config・リンク・receiptの現在値を一括照合し、既知の変更だけを復旧してPHP-FPM→nginx→元timerを再開する。未知の差異、操作結果不明、公開開始後の失敗では現在値を保持して保留する。

```sh
python3 -I -S -B /root/approved-payload/usr/local/lib/mail-platform-update/roundcube_rollout.py restore \
  --root / --evidence /root/approved-mail-settings-rollout --apply
```

## 更新器へ未登録の環境

更新器のservice／timer・所有receipt・installed.json・availability設定がない環境には、明示的なcomponent-only経路を用意している。plugin・既知core修正の逆適用・Roundcube configを配置し、独立した/run/lock/mail-settings-rollout.lockを取得する。更新器のreceiptとunitは作成しない。既に更新器が存在する環境でこの経路を選ぶと停止する。準備後の登録記録出現も変更前に拒否する。

```sh
python3 -I -S -B /root/approved-payload/usr/local/lib/mail-platform-update/roundcube_rollout.py prepare \
  --root / --payload /root/approved-payload \
  --evidence /root/approved-mail-settings-rollout --component-only \
  --hostname mail.example.net --peer mx.example.net
```

apply／restoreは上記と同じplan hash付き入口を使う。登録済み環境は独立lockと既存update.lockの両方を取得する。未登録環境の故障時も、config・コード・リンクの既知差分だけを復旧し、未登録状態を保持する。両経路の実nginx／PHP-FPM unitと通常CLIを隔離検証した。

初回の更新器登録は専用enrollment工程で扱う。本番の個人Sieve・別writer・保存世代は、適用前の現行確認が必要である。「詳細ルール」は既存Sieveを構造として読み込み、複合条件・複数処理・拡張引数をフォームで編集する。既存個人ルールを編集する場合はinclude内のscopeを維持し、有効Sieve全体を編集する場合はその構造を保持する。元のsourceと保存世代は引き継ぐ。

## 確認済みの範囲

専用Debian 13の隔離環境で、実Roundcubeログイン・新設定API、MFA／失効、移行前の個人Sieve・合成メール・UIDL履歴の保持、配置前の競合拒否、公開前復旧と公開後保留を確認した。実サーバーの適用とPHP-FPM停止／開始は、具体的な対象・hash・停止影響を提示して承認後に実行する。
