# MI SYSTEM Mail Platform

Debian 13 amd64向けメールサーバーの導入・管理・署名付き更新コードです。Roundcubeと独立plugin、クライアント証明書、送信量制限、転送・Sieve、監視、ウイルス・添付制御を組み込みます。

## 0.4.2

[署名付きReleaseと配布資材](https://github.com/ken-misystem/mail-server-admin/releases/tag/v0.4.2)

0.4.0または0.4.1から直接更新できます。0.4.1の先行導入は不要です。通常構成・世代登録済み構成の両方に対応し、環境固有設定・メール・UIDL・DB・Sieve・履歴を保持します。Rspamdのsymbols.cache保存修正も同じ更新資材と新規導入資材へ組み込みました。

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

0.4.0公開時の新規導入・0.3.0移行・復旧証拠を再利用し、0.4.2では公開0.4.0の実更新器による直接更新、世代と通常コードの混合更新、実package更新・故障復旧、新規導入差分を隔離環境で確認しました。実メール試験送信は行っていません。実ACME外部API・実VPSの全経路・全メーラー接続を今回確認したものではありません。

## ライセンス

独自コードはMIT、著作権表示はMI-SYSTEMです。第三者コードには元のライセンスを保持します。旧Roundcube修正patchはGPLv3以降、ClamAVはGPLv2、Dovecot/PigeonholeはMIT/LGPL等の各条件を適用します。

[ライセンス範囲](mail-platform/LICENSING.md)・[第三者一覧](mail-platform/THIRD_PARTY.md)・[配布方式](mail-platform/DISTRIBUTION.md)

Rspamdの固定debと対応ソースを署名資材へ収録します。他OS packageは導入先APT、ClamAVは公式資材、Dovecotは対応sourceから現地準備します。公式ウイルス定義、私有kit、顧客データ、秘密鍵・資格情報は公開資材に含めません。
