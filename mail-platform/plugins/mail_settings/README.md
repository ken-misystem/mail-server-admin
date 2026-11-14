# MI-SYSTEMの転送・フィルター・休暇応答プラグイン

独自実装のライセンスはMIT。Roundcubeの標準plugin APIとOS packageのNet_Sieveを呼び出す。managesieveのparser／engine／画面コードを複製していない。

## 設定と動作

- 有効化はmail_settings_enabled=trueとpluginsへのmail_settings登録で行う。標準managesieveを同時に登録した場合は操作を拒否する。local_auth_gateとsession_epoch_guardを使う。
- 新規導入用の候補はbuild.pyまたはrelease_assets.py prepareで生成する。既定はplugin。--roundcube-settings pluginでも明示できる。旧構成を指定する場合は--roundcube-settings legacyを使う。既存環境の設定移行には専用手順が必要である。
- DebianのWeb側パスへroot所有リンクを登録する。新規installerは登録・属性確認・条件付き復旧を行う。
- 接続先は127.0.0.1の4190。STARTTLSと証明書名検証を必須とし、成功後にログインする。mail_settings_sieve_peer_nameには導入先の証明書名を設定する。
- ロック領域は/var/lib/roundcube/mail-settings-locks。PHP実行UID所有の0700とし、ファイルは0600。新規installerがwww-data所有で作成する。
- 既存の個人Sieveは保全コピーを先にincludeする。既存ルールでstop、keep、redirect等を実行する場合、その結果が先に適用される。このプラグインのフォームは追加ルールを編集する。
- 「詳細ルール」は既存scriptを字句・条件・ブロックの構造へ読み込み、元のコメント・空白・引用・複数行文字列を保持する。変更しないparse/renderは元バイトと一致する。構文はRFC 5228を参照して独自実装した。
- 複数条件のallof/anyof/not、if/elsif/else、複数処理、入れ子、順序変更、複製、ルール名、無効化／再有効化を扱う。無効化はif/elsif/elseの連続する分岐をまとめてif falseで包む。
- 13種類の条件雛形と20種類の処理・分岐雛形を用意した。header/address/envelope/exists/size/body/date/currentdate/string/spamtest/duplicate、保存／コピー／転送／拒否／vacation／フラグ／ヘッダー編集／変数／通知／include等を編集できる。比較タグ・comparator・regex・値一覧・拡張引数も構造内で編集する。ManageSieveが通知した対応拡張から追加メニューを絞り、最終構文と拡張の検証はPUTSCRIPTに任せる。
- Sieveファイルの読込み・保存済みsourceのダウンロード、名前付きルールの作成・参照・有効化・名前変更・未使用ルール削除を扱う。新しい名前の作成は一時名で検証した後のRENAMESCRIPTで行い、同名の別更新を上書きしない。有効ルール、保存世代、参照中または動的includeを含み参照関係を確定できないルールの削除は拒否する。
- 全体編集と既存個人ルールの編集範囲を分ける。既存個人ルールを編集してもinclude内のreturnとstopのscopeを維持する。従来の簡易転送・1条件filter・vacationフォームとformat 1保存世代も利用できる。
- 1scriptは64KiB、構造は最大32階層・8,192要素、HTTP要求は1MiB。空白・コメント欄への命令挿入を拒否する。最終保存前にサーバーが構文を検証し、拒否時は有効ルールを維持する。
- 変更ごとに内容hashの別名で保存し、構文検証・読戻し・元のactive確認の後に有効化する。既存scriptと保存世代を保持する。64scriptを超える保存は拒否する。
- 結果不明時は読取り更新で状態を確認する。自動再送は行わない。

## 同時更新と復旧

同じPHP実行系の操作は本人ごとのflockで排他し、画面のrevisionと有効script／保全コピーを照合する。追加したDovecot native pluginは、認証後の実homeにある`.mail-settings-session.lock`を接続終了まで保持する。同じ本人の別プロセス・別接続元IP・別Dovecot世代・同じhomeへ集約される別名も同じ排他を使う。競合するManageSieve接続は拒否する。既存の画面revision照合は維持する。管理Sieve publisherは別のbefore scriptを扱う。

同じ本人のManageSieve接続は1件である。読取り中やアイドル中の接続も排他を保持する。別のメールアプリが設定接続を維持している場合は、その設定接続を閉じてからGUIを開く。競合時はDovecotが接続を終了し、`settings_busy_or_lock_unavailable`をサーバーログへ記録する。別本人と通常IMAPログインはこの排他の対象外である。通常切断・プロセス終了でkernelが排他を解放する。ロックファイルは削除しない。

導入は[NATIVE_ASSETS.md](../../NATIVE_ASSETS.md)のABI/source/module照合を使い、Dovecotのグローバル`mail_plugins`へ登録する。既存環境への初回採用は、旧ManageSieveセッションを終了して全世代に同じpluginを導入する移行工程である。本番採用は別途承認する。

管理CLIは次の固定入口を使用する。`list`、`activate 名前`、`deactivate`、`delete 名前`を扱い、`doveadm exec managesieve -u`を介して同じ排他に入る。直接の`doveadm sieve`やrootによるファイル編集はこの排他を経由しない。

```sh
sudo python3 -I -S -B /usr/local/lib/mail-platform-update/sieve_lock.py admin \
  --owner user@example.test list
```

保存済み世代はプラグインから選択して復旧できる。メール本文・Maildir・UIDLは扱わない。旧画面へ切り戻す場合、最新Sieveがincludeを使うため、旧managesieveの画面が扱えることを別途確認する。scriptを過去状態へ無条件に巻き戻さない。

文書形式の世代は元のscriptをバイト単位で復旧する。名前変更・削除の結果が不明な場合も自動で再送しない。削除前のsourceは内容hash付き保存世代へ保持する。Sieve拡張の動作はサーバーの対応と設定に従う。

[Sieve文法](https://www.rfc-editor.org/rfc/rfc5228)・[ManageSieve](https://www.rfc-editor.org/rfc/rfc5804)・[Vacation](https://www.rfc-editor.org/rfc/rfc5230)。

実Roundcubeからのログイン・新設定保存、MFA未完了の拒否、認証世代失効を専用Debian環境で確認した。移行と復旧のCLIは[MIGRATION.md](MIGRATION.md)を参照する。

標準PHP-FPM構成向けに、nginx→PHP-FPMの終了／逆順の再開をまとめた明示適用ランチャーを用意した。登録済み環境は更新receiptを採用し、未登録環境はcomponent-only指定でプラグインを配置する。plan hashで適用内容を照合し、公開前の既知差分だけを復旧する。世代別Web構成ではroute移行の工程が必要である。
