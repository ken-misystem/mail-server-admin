# MI SYSTEM Mail Platform

Debian 13 amd64向けメールサーバーの導入・管理・署名付き更新コードです。Roundcubeと独立plugin、クライアント証明書、送信量制限、転送・Sieve、監視、ウイルス・添付制御を組み込みます。

## 0.4.7

[署名付きReleaseと配布資材](https://github.com/ken-misystem/mail-server-admin/releases/tag/v0.4.7)

Roundcubeとメール管理画面に、IDを入力せず端末の登録済みパスキーを選ぶログインを追加しました。発見できないキーはID指定のパスキー認証で利用できます。従来のパスワード経路も使えます。既存サイトのRoundcubeでは、メール接続用の追加設定を有効にしてからパスキーログインを利用します。

## 0.4.6

[署名付きReleaseと配布資材](https://github.com/ken-misystem/mail-server-admin/releases/tag/v0.4.6)

0.4.0～0.4.5から直接更新できます。中間版の先行導入は不要です。通常構成・世代登録済み構成の両方に対応し、環境固有設定・メール・UIDL・DB・Sieve・履歴を保持します。Rspamdのsymbols.cache保存修正も同じ更新資材と新規導入資材へ組み込みました。

0.4.6では、ダッシュボードと「容量・稼働状況 → 通知設定」に内部障害通知の停止・再開を追加しました。現在の通知設定と処理状態を表示し、DKIMの正常時は完了の一文だけを表示します。停止中も稼働監視は継続します。

0.4.5では、既存環境を初回登録したあとに、更新・DKIMの定期確認が一度で止まる問題を修正しました。初回確認は15分後、以降は確認完了から15分間隔（systemdの遅延設定あり）です。停止済みの環境では、管理者が初回専用のタイマー設定を確認し、標準タイマーへ戻してください。

0.4.4では公開DNSのTXT表記差によるDKIMの誤った伝播待ち判定を修正しました。DNS登録済みで安全条件を満たす保管済み鍵は、共通更新処理で有効化します。DNS未登録の環境では更新を完了して手動対応項目を残します。

0.4.3以降では既存コードの所有者・グループ・modeを保持し、旧版の既知POP属性不整合を修復します。DKIM不足鍵の補完、公開TXTの提示・照合、同値の重複設定整理を新規導入・更新の共通処理に組み込みました。DNS未登録や照会障害は更新を止めず、ダッシュボード上部に手動対応チェックリストを表示します。秘密鍵はホスト外へ出しません。DNS登録・ポート公開・通知有効化を自動実行しません。DKIM設定の整理時は条件付きでRspamdをreloadします。

[DKIMの手動対応と再確認](mail-platform/DKIM_CHECKLIST.md)

## 新規導入

専用の空Debian 13 amd64とsystemdを使用します。署名とSHA256を確認し、サイト設定、私有kit、TLS/CA、バックアップを準備してください。署名公開鍵の信頼は別経路でも確認してください。

- [導入環境・手順](mail-platform/INSTALLATION.md)
- [初期ログインと公開制御](mail-platform/INITIAL_SETUP.md)
- [証明書の取得・更新・CA世代](mail-platform/CERTIFICATES.md)
- [native資材の取得・現地build](mail-platform/NATIVE_ASSETS.md)

環境チェックを最初に実行します。既存アプリ、ポート、配置先、所有者・権限の競合を検出すると停止します。初期UIはloopback限定です。期限付き初期資格情報の変更とパスキー登録後に、管理者が明示公開します。VPS側の公開ポートもその判断後に設定してください。

## 更新

管理画面で手動承認と自動更新を選択します。更新器が署名、対象版、所有ファイル、構成を照合して適用し、障害時には既知変更だけを条件付き復旧します。

通常構成では管理画面/RoundcubeのPHP-FPMと関連workerが一時停止します。世代構成では既存frontを維持して新workerへ切り替えます。旧Rspamdを更新する場合はMilter判定接続が一時停止します。SMTP・IMAP・POP・DBの停止は要求しません。

[共通更新契約](mail-platform/COMMON_UPDATE.md)・[更新と署名](mail-platform/RELEASE.md)・[検証資料](mail-platform/VALIDATION.md)

既存の導入・更新・復旧の検証結果を再利用しました。0.4.5では隔離Debianのsystemdで、初回の待ち時間とその後の反復を確認しました。

## ライセンス

独自コードはMIT、著作権表示はMI-SYSTEMです。第三者コードには元のライセンスを保持します。旧Roundcube修正patchはGPLv3以降、ClamAVはGPLv2、Dovecot/PigeonholeはMIT/LGPL等の各条件を適用します。

[ライセンス範囲](mail-platform/LICENSING.md)・[第三者一覧](mail-platform/THIRD_PARTY.md)・[配布方式](mail-platform/DISTRIBUTION.md)

Rspamdの固定debと対応ソースを署名資材へ収録します。他OS packageは導入先APT、ClamAVは公式資材、Dovecotは対応sourceから現地準備します。公式ウイルス定義、私有kit、顧客データ、秘密鍵・資格情報は公開資材に含めません。

