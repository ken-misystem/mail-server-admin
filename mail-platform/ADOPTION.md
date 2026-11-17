# 既存稼働サーバーの初回登録とnative修正

## 環境固有の監視参照を保持する共通修正（未公開）

監視collectorを環境ごとに改変せず、`/etc/mail-management-operations-v1/environment.json` に参照先を分離する。初回移行plannerは、信頼済みの既存collectorのCOMMANDS定義から、固定形式のpostqueue引数とCertbot lineageをASTで取得する。既存コードは実行しない。参照先の存在・root所有・権限・リンク構造を照合した場合だけ設定追加を計画する。元コードが `postqueue -j` の場合は `/etc/postfix` を明示する。

環境設定が既にある場合はその値を検査して、改行・空白を含む元バイトを保持する。設定を更新器のコード所有一覧へ含めず、通常更新・コード復旧では置換しない。未対応COMMANDSや参照先欠落は自動補正しない。

登録済み旧版に環境設定がない場合、通常更新は `monitor_environment_explicit_migration_required` で停止する。別途レビューした設定移行が先に必要である。過去の移行で参照先を失った環境では、現行の誤った参照から推測せず、保存済みの移行前コード・実属性を照合して計画する。全体の初回移行を再実行しない。適用承認・固定計画・退避・CAS・読戻しは従来どおり必要である。

## 本番専用の初回契約

初回移行資材は `install_ready=false` を保持する。正式署名だけで通常の新規導入・自動更新へ流用しない。専用検証器は `scope=existing-host-only`、外部承認digest、本番plan・配置内容・保全情報・停止保護契約・新unit初回契約・Sieve実効値を結合する。

新規更新UI/socket/timerは既存サービスの復帰後に初回起動する。初期モードはmanual、GitHub tokenは空、UIは許可UIDのUnix接続のみ。更新workerをその場では起動せず、初回確認を15分後に設定する。元からunit・設定・手動要求が存在する場合は停止前に拒否する。enable/startの未確定結果はjournalを保持し、自動再試行しない。

include構成のDovecotでは元mainへ専用includeを追記し、各protocolで継承されていたplugin値も保持する。実効値は停止前・停止後・候補配置後・再開後に照合する。旧設定・個人Sieve・Maildirは初期化しない。

新規導入用installerは既存稼働サーバーへ使用しない。更新器の登録がないサーバーを、過去のパッケージ版として登録して更新検査を通してはいけない。

初回登録では、コード・設定・DB schema/grants・UID/GID・有効Sieve・Maildir/UID・資格情報・timer・外部連携を棚卸しし、同じ状態を再現した隔離環境で移行と復旧を確認する。`adoption_plan.py`は未確認項目や保護データへの書込みを拒否するplan検査である。

`initial_adoption.py`に初回ファイル配置・所有登録・復旧の処理を実装した。固定plan/候補hash、書込み直前CAS、root専用journal、排他、実配置の読戻しを要求する。全コードの確認とhealthの合格後に、実際の対象版・Release hashを登録し、更新モードはmanualから開始する。中断時は保存journalから復旧し、再開要求後・未知変更は自動で巻き戻さない。事前確認で止まった場合はサービス再開を要求しない。

`adoption_components.py`は現行ファイルから証明書actorのmanifest参照、Sieve排他module、Roundcubeの既知差分の原状化と独立pluginを結線する。未知の既存値を拒否し、設定の一般値・資格情報を初期値で置換しない。`adoption_services.py`は固定unit一覧のtimer停止、oneshot終了待ち、socket/worker停止と元の活動状態への再開を担当する。enable/disableは行わず、操作要求を先に記録する。結果不明の操作は再試行しない。

`adoption_host.py`は実systemd操作、Web worker停止の確認、証明書/更新排他、停止中の構文検査、pluginリンクのCAS復旧を接続する。ファイル配置前の部分停止は元timerの復旧対象とする。サービス再開要求後の不確定は自動復旧しない。

`adoption_review.py`は観測済みsystemd依存関係から停止の波及範囲と保護契約を作る。停止外のdaemonはPID・活動状態・unit定義を固定し、保護対象のoneshotは正常な自然周期を許容する。未知の停止依存、未審査POP worker、保護定義変更を拒否する。`adoption_host.py`の停止前後・再開前後・復旧境界に読取り検査を接続する。

`adoption_binding.py`は既存の製品公開鍵pin、外部から指定したreview digest、正式署名、全payload一覧、native要件、保全情報、停止契約、compiler入力、最終plan/配置内容を結合する。検証済みarchiveからだけ候補を生成し、保護unit定義への書込みを拒否する。本番factoryは保護検査を必須にする。初回登録資材に架空の旧版update-contractを含めない。

**実サイト向けの最終plan、正式署名、最終ランチャーの承認は未完了である。** 署名・ready条件のない準備資材は適用できない。隔離試験の合成署名鍵や検証用readinessを本番で使ってはいけない。通常の0.3.0移行処理に架空の旧版receiptを渡すことも禁止する。DB/資格情報/Maildirの初期化処理は含まない。

## Rspamd修正の保持

`native_requirements.py`を手動/自動更新の共通経路へ追加した。初回登録でroot:root/0600の `native-components.json` を採用したサイトは、次の条件を満たす署名資材だけを更新候補として使用する。

- 固定native要件descriptorが登録済み要件と一致する、またはnative保持descriptorに従って既存登録と実runtimeが一致する。
- package版・architecture・修正library hash・稼働中masterの読込みdevice/inodeが一致する。
- 判定は更新開始前、activate前、health前に行う。修正要件の省略、異なる版、未知libraryは拒否する。

`release_assets.py prepare --native-requirements <reviewed-json>` で要件を署名対象archiveへ含められる。既存の署名済みReleaseは変更しない。

この機構は、**導入済みnative修正の保持・再利用を検査する機構**である。旧Rspamdのインストール・自動修復・restart/reloadは実行しない。native自体を更新する場合は別途検証済みnative migrationが必要である。署名済みnative-preservation-v1.jsonを持つコード更新では既存nativeを変更せず保持する。登録がある場合はその登録と実runtimeを照合し、登録のない公開0.4.0でもアプリコードだけを更新できる。native修正を新たに適用したとは報告しない。

今回の既存サイト移行候補は `install_ready=false`。初回移行・設定保全・修正結合のreadinessが完了するまで、正式署名/公開/本番適用しない。既存の成功証拠はその入力と範囲が一致する項目だけ再利用する。

メール・UIDL・queue・台帳・DB業務行・秘密・履歴はReleaseに含めず、復旧でも削除/巻戻ししない。外部MX、DNS/FW、残着POPやセカンダリの起動状態をパッケージ初期値で変更しない。

0.4.2共通更新では上記読取りゲートに加え、署名された`rspamd-package-v1`の専用移行を実行する。旧版は固定debで修正し、修正済み版は再導入しない。詳細は[共通更新契約](COMMON_UPDATE.md)を参照。
