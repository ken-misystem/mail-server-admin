# Rspamd 3.12.1: symbols.cache保存修正

このディレクトリはDebian `rspamd 3.12.1-1`向けのソース修正とビルド手順です。
修正版の版名は`3.12.1-1+0misystem1`です。
既存の署名付きMail Platform v0.4.0資材は変更していません。
**v0.4.0のインストーラー・更新器は、このパッチを自動適用しません。**
この記載は0.4.0公開時の状態です。0.4.2候補は対応ソースとdebを署名対象に含み、専用native migrationで導入・復旧します。[共通更新契約](../../../COMMON_UPDATE.md)を参照してください。

## 修正内容

3.12.1の`save_items()`は一時ファイルを作成しても`write_output()`を呼ばず、
終了時に一時ファイルが削除されていました。また`fdopen/fclose`とファイル管理クラスが
同じFDを所有していました。修正は保存確定・FD所有権・ロック後のtruncate・部分書込みと
EINTR処理です。既存cacheは書込み失敗時に保持します。
判定点数、設定、Lua、unit、3.12.1の統計値丸めは変更しません。
`symbols.cache`は統計情報であり、メール本文や迷惑メール学習DBではありません。

## ソース準備

Debian 13 amd64の専用ビルド環境を使用してください。本番でビルドしないでください。
`source-lock.json`に記載したDebian公式URLから3ファイルを取得し、`cache/`へ置きます。
このhelperはダウンロード、APT操作、パッケージ導入、サービス操作を行いません。

```sh
python3 -B mail-platform/third-party/rspamd/prepare.py \
  --source-cache ./cache --output ./rspamd-build
```

`dpkg-source`と`patch`が必要です。3入力・パッチ・テストのSHA256を照合し、
新しい出力先だけに展開します。変更前後のC++ファイルのhashを要求し、
異なる版・改変入力・既存出力先を拒否します。成否・実終了値・標準出力／エラーは
`rspamd-build/`に保存します。失敗した作業領域は削除せず保持してください。

## ビルドと新しい環境での検証

依存関係は固定Debian sourceの`debian/control`の`Build-Depends`に従います。
専用環境の管理者が確認・導入した後、通常ユーザーで実行します。

```sh
cd rspamd-build/source
dpkg-checkbuilddeps
dpkg-buildpackage -b -uc -us -j2
```

既存の成功済みビルド証拠の再利用では、この処理を再実行する必要はありません。
新たにビルドした場合は生成debの版・依存・内容を確認し、専用環境で
導入→正常起動→cache保存→次回起動での読込み→切戻しを検証してください。
ビルドパス・toolchain・タイムスタンプによってdebのバイト列は変わります。
過去の検証debとbit-for-bit一致するという保証はありません。

同梱の`test/rspamd_cxx_unit_symcache_persistence.hxx`は5ケースです。
実テスト実行時は`rspamd-test-cxx`がビルドした`librspamd-server.so`をロードしていることを
`ldd`で確認してください。OS導入済みの旧libraryをロードした結果を採用しないでください。
このテストはcacheの保存／故障保全を対象とし、SMTP送信を行いません。

## 稼働環境へ適用する場合

このディレクトリに汎用の本番自動適用ランチャーは含めていません。
ホストごとの承認・退避・サービス制御・復旧計画が必要です。

1. 現行版、依存、設定hash、cache属性、保護サービス、Milter障害時動作を保存する。
   旧debも取得・検証して保持する。未知の版へこの3.12.1専用パッチを適用しない。
2. パッケージの自動サービス操作を対象限定で制御し、既存policyを上書きしない。
   導入計画に想定外の削除・依存変更があれば中止する。
3. 必要なrestart後は、systemdの`active`だけで起動完了と判定しない。
   masterのPIDと開始時刻、子worker起動、SIGHUP handler登録とblock解除を確認する。
   新libraryのdevice/inodeを`/proc/<pid>/maps`と照合する。
   無関係なshared memoryの`(deleted)`表示を誤ってlibrary不一致と扱わない。
4. 安定したmasterを複数回確認後、保存確認用reloadを1回だけ行う。
   既存cacheを削除せず、inode置換、形式、所有者、master存続を確認する。
   restart中のMilter判定接続は一時停止する。実際の配送影響は各Postfix設定で確認する。
5. 自然稼働・新エラー・保護サービスを別接続で読戻す。結果不明・未知差異・保存要求後の
   不確定状態で操作を繰り返さない。メール・queue・cache・履歴を保持して調査する。
   既知かつ確定した変更だけを旧debへ条件付き復旧する。

## 検証の区分

保存済み証拠で確認した項目：cacheの5ケース／65assertions、実debの導入・起動・保存・
再読込み・切戻し6条件、最終版と検証済み版の8実行ファイルのbyte一致、追加依存0。
旧検証の丸め期待値不一致は修正後に未完了ケースだけ確認し、元FAILを保持しています。
本番の保存確認ではcacheのinode置換、master維持、自然2観測を完了しました。
今回の公開作業では、ソース準備helperの新規検証と既存証拠のhash照合だけを追加しています。
旧成功試験・本番サービス操作・実メール送信は再実行していません。

公開用helperが作る新しいbuild tree一式からの再ビルド・Mail Platform全体の
新規導入／更新試験は今回行っていません。既存v0.4.0の導入・更新合格を、
この新しいパッケージの自動配布試験として扱わないでください。

ライセンスと変更表示は[NOTICE.md](NOTICE.md)を参照してください。
