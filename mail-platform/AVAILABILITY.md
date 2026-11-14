# 配送を継続する更新候補

0.3.0の通常更新はformat 1を使用する。検証済み契約ではPHP-FPMと更新画面brokerを切り替え、Postfix/Dovecotの状態とPIDを確認する。適用する契約と現在の登録版を照合する。

世代切替え方式のformat 2はサイト固有の登録が必要である。2026-11-14に、管理画面・Roundcube・実SQL送信量policyの初回登録、全payload更新、故障時復旧、起動時の世代復元を隔離環境で確認した。`readiness.json`の`delivery_preserving_updates_validated`はこの登録範囲の確認結果を示す。署名付き契約のconfiguration hashと全利用元の対応を各サイトで照合する。現在の配布候補はinstall_ready=falseで生成する。

## 実装

- 既存署名検証・更新トランザクションから format 2 の契約を `generation_update.GenerationUpdate` へ渡す。format 1 は従来の `CodeUpdate` を使用する。
- 登録済みコード範囲を全ての利用コンポーネントへ対応付ける。共有コードの利用元が選択から欠ける変更、未登録ファイル、unit変更、追加・削除、現行hash不一致は適用しない。
- 読取り処理とWebは別世代を起動・確認してUnix経路を切り替える。既存接続は旧世代へ固定する。独立FPM masterにより新旧PHPコードを混在させない。
- writerは新規要求を待機させ、旧要求の完了・旧writer停止後に新writerを起動する。既存アプリの単一writer lease・FULL commit・重複防止は維持する。待機超過・backend障害は451。backendへの失敗要求を別世代へ再送しない。
- 診断・CAS・世代inventory・実unit操作・復旧状態をroot専用トランザクションへ保存する。操作結果不明、未知route、未完了要求は保留する。強制終了や無条件の再実行は行わない。
- 更新画面には署名検証済み契約の方式と対象コンポーネントを表示する。方式の表示は、そのホストの導入完了証明ではない。

## 初回組込みの必須条件

`/etc/mail-platform/availability.json` をroot所有0600で配置する。設定のcanonical JSONのSHA256を署名付き契約の `configuration_sha256` と一致させる。

```json
{
  "format": 1,
  "generation_root": "/var/lib/mail-platform-generations",
  "components": {
    "web": {
      "kind": "web",
      "roots": ["/opt/example-web"],
      "route": "/etc/mail-platform/web-route.json",
      "control": "/run/mail-platform-web-front/control.sock",
      "runtime": "/run/mail-platform-generations/web",
      "unit": "mail-platform-web@.service",
      "template": "/etc/mail-platform/web-fpm.conf",
      "drain_seconds": 60,
      "health": {"kind": "fcgi", "request": "/opt/example-web/health.php", "reply": "READY"}
    }
  }
}
```

これはパスの例であり、稼働サーバー用設定ではない。登録前に次を照合する。

1. 管理画面・Roundcube・共通ライブラリー・policy・publisher・collector・証明書gate/backendを含む全利用元と、現在のUID/GID・socket・権限・依存を対応付ける。
2. source treeはroot所有・group/world書込み不可・通常ファイル/ディレクトリーだけとする。symlinkを含む既存treeは自動採用しない。書込み先cache/session/ログ/メール/DBはコード世代の外へ分離する。
3. `generation_units.fpm` の生成結果を、現行FPM poolの拡張・環境・timeout・PHP値・アクセス制限と照合する。`writable_paths` で必要な既存状態ディレクトリーを明示する。生成器の既定値だけを本番設定としない。
4. stable frontは更新対象の外へ常設する。起動は `python3 -I -S .../generation_entry.py front` と固定引数を使う。controlはroot専用、公開Unix socketは接続元UID照合と限定group、RuntimeDirectoryの終了時清掃を必須とする。stale socketを自動削除する実装はない。
5. routeは `{ "generation": "g...", "socket": "/run/.../backend.sock" }` のroot所有JSON。既存世代・front PID・正常な要求を確認してからreceiptとunit templateを登録する。
6. サイト固有のhealth、要求時間、同時実行・資源上限、writerの終了・lease解放・再openを確認する。検証fixtureの上限値を本番の能力としない。

署名対象の更新契約例:

```json
{"format":2,"from_version":"0.1.1","to_version":"0.2.0","components":["web"],"configuration_sha256":"<installed canonical configuration SHA256>"}
```

`build.py --update-contract` と `release_assets.py` は同じ検証器を使用する。設定hashを配布側で推測しない。異なる登録構成を同一契約で一括自動更新しない。

## セカンダリ

`secondary_mx.render` は宛先を限定したrelay、主系への固定経路、検証付きTLS、必須milter、サイズ上限を生成する。署名済み宛先一覧は期限・単調増加世代を検査し、期限切れ/不正署名は451、宛先不存在は550、他ドメイン中継は554とする。

配置・公開・MX登録はこの候補で自動実行しない。独立した永続queue、主系停止中の検査/宛先情報、TLS名と信頼CA、主系の転送元信頼条件を実環境で確認する。受信したqueueを残したまま撤去しない。

## 確認済み範囲と未確認

隔離Debian 13で、実署名付き更新経路・独立FPM・旧要求完了・異常health時の復旧、実Postfixの進行中SMTPとの共存、セカンダリ再起動後のqueue保持・主系復帰後のTLS/LMTP配送、検査不在時451を合成データで確認した。

実Rspamd/ClamAVとセカンダリの検査同等性、原接続元に基づくSPF/DMARC、長時間IMAP/POP/証明書セッション、実サイト全コンポーネントの世代移行は未確認である。セカンダリだけでは587/993/995の継続利用を実現しない。

追加の隔離検証では、実TLSGateと非root/capabilityゼロのgate、実Postfix SASL、実Dovecotを使い、587/993/995の既存接続と新規接続の世代切替えを確認した。既存セッションの保持、旧世代の停止保留、失効時切断、backend不在時の拒否に合格した。registryと証明書は合成値であり、本番のDB/CRL運用は既存証拠を参照する。

`backend_fronts` の登録を省略したgateは従来の接続先を使用する。登録時は3プロトコル全てのroot所有frontend Unix socketとpeer UIDを指定する。`generation_units.certificate_front` は、現行のgate UID/GID・group・loopback backend endpointから初回組込みの候補を生成する。実環境のunit依存と、複数プロトコルが共有する旧Dovecotの停止条件を照合する。旧DovecotはIMAP/POP両方の処理中接続が解消するまで保持する。

中継の最終応答を送信待ちのままbackend EOFで破棄する不具合を修正した。通常のソース登録・ビルドで適用し、部分書込み時の完了と失効時の即時切断を新規検証した。証明書runtime manifestが変わるため、現在の更新器が要求する専用migration hookによる初回採用を準備する。

OS・DB schema・Dovecot/Postfix等のネイティブ更新、front自身の更新は別の保守工程とする。受信継続・配送遅延・接続継続の条件を区別し、無停止を保証しない。

## 追加した旧世代の終了管理

長時間接続が残っているWeb/readerの更新は、新世代のhealth成功後にcompleteとなる。旧接続は旧世代に固定し、`retirement_pending`を取引と更新画面へ表示する。旧世代の停止待ちで更新を失敗・復旧へ移す処理を修正した。

既存の更新確認は新Releaseがない場合も旧世代の終了条件を確認する。前回の署名付きinstallerの保存hash・root属性・設定/route/inventoryを照合して`retire`を呼ぶ。旧接続が残る間は次の更新取引を開始しない。全接続終了後に旧unitを一度停止し、繰返し確認では再起動しない。旧unitのPID差異・未知のroute・操作結果不明は保留する。

同じunitを共有する全入口を更新対象へ含め、旧世代名の一致を要求する。IMAP/POPなどのreaderは、全入口の旧接続数が0になるまで共通旧unitを維持する。writerは全入口をpauseしてから全要求をdrainし、共通旧unit停止・新unit起動を各1回行う。復旧も同じgroup単位で処理する。routeは元のroot所有・modeを原子的に保持する。

実systemd・2つのstable front・独立PHP-FPM・署名付き更新で、新要求の新世代移行、残る旧要求の保持、後続確認での停止と次更新の保留を確認した。実PHPで待機表示とエスケープも確認した。

## 送信量policyの世代引継ぎ

送信量policyのstable frontは`--mode policy --policy-nonce`で起動する。generation backendは同じ送信量コード領域の`generation_launch.py`を使う。通常の`launch.py`は従来の直接接続方式を維持する。片側だけの登録は要求拒否となるため、同じ初回planへ含める。

frontは接続ごとに32byteの乱数を生成し、要求に固定の世代用nonceを追加する。接続元が同じ項目を指定した要求は451で拒否する。backendはpeer UID照合後にnonceを検査し、検証済みの計上SQL・FULL commit・単一writerへ渡す。これによりbackendが変わっても同じ接続・instanceの重複判定を維持する。失敗した要求の別世代への自動再送は行わない。

policyのhealthは`request=mail_platform_generation_health`と空行を使う。許可peerからの専用backend照会で、現在のDB上限2profileと停止snapshotを読み、計上を行わず`action=DUNNO`を返す。DB障害時は451となる。通常要求の1秒cacheとhealthの現在値取得を分ける。`health`へ正の`peer_uid`・`peer_gid`を両方指定すると、rootの確認処理はその本人へ権限を落とし、capabilityゼロ・NoNewPrivilegesで照会する。

新しい隔離検証では、実非root writer・2つの非root front・共用SQLiteで、切替え前後の重複拒否、独立接続の計上、待機超過451、health故障後の旧lease再open・receipt/台帳保持を確認した。履歴と秒集計は3件/3宛先で一致し、integrity_checkはokだった。SQL readerと本番のDB/CRL運用は保存済み証拠を再利用した。

この段階で追加経路の検証を完了した。その後の実SQL/CRL、サイト登録、更新・復旧の確認結果を末尾の2026-11-14節に記録する。本番用の登録内容はサイト別に照合する。

## 初回証明書gateの採用と共有メール状態

`certificate_enrollment.stage` は現在のmanifestの全pinとguardを照合し、公開ファイルだけを新領域へ保護コピーする。transport/gate_runtime/backend_frontsの3モジュールを更新した新manifestとgate設定を生成し、他の4actorが参照する現行release・設定・資格情報は変更しない。gate unit内だけのread-only bindで新しいviewを採用する。依存の削除は完全なunit fragmentを対象とし、既存drop-inを保持する。

明示的な初回入口は `python3 -I -S -B /usr/local/lib/mail-platform-update/enrollment_entry.py --plan /etc/mail-platform/enrollment-plan.json prepare|adopt|recover` である。planはroot所有・書換権限限定のサイト固有承認資料であり、自動生成した例を本番へ適用してはならない。prepareは固定3コードpinと現行manifest/config/unit/drop-inを検証する。adoptは稼働済み3frontendを要求し、専用viewとgate unitを採用してdaemon-reloadとgate restartを行う。正常終了も `unit_adopted` であり、サイト固有のアプリ正常判定や更新器全体の登録完了を意味しない。結果不明のunit操作・未知差分は復旧を保留する。復旧済み状態でのrecover再実行は再起動しない。

隔離Linuxで9個の実unit、実systemd-socket-proxyd、nonroot/capabilityゼロ、実bootstrapによる旧→新→旧manifest view、共有Dovecotの停止依存分離を確認した。SMTP bridgeのunit試験はbanner/QUITだけの合成backendを使い、実Postfix AUTH/TLSの既存証拠を再利用した。

2つの実Dovecot 2.4.1が同じ合成Maildir/indexを使用し、IMAP UID/UIDVALIDITY・POP UIDLの一致、合成1件追加後の旧UID維持、片側停止・再開後の一致を確認した。IMAP/POP両routeが新世代になり、旧接続数が両方0になるまでは共通旧Dovecotを終了しない。本番8メールボックスはhost/private Dovecotのprocfs rootからMaildirとUID状態ファイルのdevice/inode一致を読取り確認した。本番Maildirへ検証プロセスを起動したりindexを書き換えたりはしていない。

現行gateはCanReload=noのため、初回採用では一度のgate再起動とクライアント再接続が必要である。個々のサイトの本番採用は、そのサイトのplanと承認を確認して実施する。

## 2026-11-14の実サイト構成による確認

旧0.3.0の保存済み導入を新しい隔離コピーへ復元し、0.4.0への初回移行とhealth終端故障からの復旧を確認した。Sieveの公開module、既存設定の厳密な差分、送信停止情報のread-only bindを同じ取引で扱う。旧Sieveセッションは初回のDovecot停止で終了する。保存済みの実AUTH・lock検証はmodule/sourceの実バイト照合で再利用した。

`build.py`と`release_assets.py prepare`の`--sieve-migration-kit`と`--sieve-migration-from`は対で指定する。前者は公開moduleとmetadata、後者は旧版のversion/blueprintsを含むJSONを指す。schema、旧blueprint、ABI、設定anchor、停止・再開順が一致する対象を扱う。メール・UIDL・台帳・資格情報は移行資材へ含めない。

初回の世代登録は次の製品入口を使用する。payloadは署名検証済み候補のroot所有領域を指定する。

```sh
python3 -I -S -B /verified/payload/usr/local/lib/mail-platform-update/site_enrollment.py plan --payload /verified/payload
python3 -I -S -B /verified/payload/usr/local/lib/mail-platform-update/site_enrollment.py apply --payload /verified/payload
```

既定登録はweb、web-roundcube、policyの3成分である。既存2poolの全設定、実SQL reader、既存FULL台帳、Unix peer UID、LoadCredential、証明書stackの実DB/CRLを使う。初回はgate/owner/private SMTP、policy、FPMを停止・再開し、クライアントの再接続を伴う。管理用/通常FPMの固定socketと送信量socketはstable frontが引き継ぐ。FPMの従来のreload入口も維持する。

登録取引は`/var/lib/mail-platform-update/site-enrollment-*`へ保存する。公開前の失敗は保存されたhash/属性とPIDに一致する変更だけを復旧する。公開済み取引と結果不明の操作は保留する。世代の終了待ちとretireは既存の更新確認が扱い、起動時は`mail-platform-site-generations.service`がcurrent routeとinventoryを照合して起動する。

全payloadの署名付き更新で、旧PHP要求の2回のコード読取りが同じ旧hashを使い、新要求が新hashと実PDOを使うことを確認した。共有FPMは旧要求終了後に一度停止した。health後故障では旧route/code/receiptへ復旧し、活動中の同じpolicy接続の重複計上は0件だった。履歴と秒集計は一致した。既存の内部SMTP587・IMAP143 STARTTLS・POP110 STLS接続は切替えと復旧を跨いで継続した。公開587/993/995の証明書方式の証拠は保存済みの確認結果を再利用した。

policy frontのアイドル上限は30秒である。最初の継続確認driverはこの上限で接続が閉じた後に停止した。元FAILを保持し、成功済み更新とPHP応答を読戻した。後続の新しい故障シナリオでは活動中接続で引継ぎを確認した。

同じ検証機でcold boot後の世代起動、UIDL/UIDVALIDITY・DB・台帳・receipt・route保持と実SQL/CRL healthを確認した。初回のnspawn停止ランチャーにKillMode指定の不足があり、強制終了と起動失敗を記録した。ローカル標準定義のKillMode=mixedへ揃えた後の正常終了も確認した。

OS、DB/schema、Postfix/Dovecot等のネイティブ、stable frontと更新基盤の変更は保守工程で扱う。format 2は未登録コード・追加/削除・設定/unit変更を適用前に拒否する。標準のコード更新検証と各サイトの公開/DNS/FW・セカンダリ配置確認をそれぞれ記録する。
