# MI SYSTEM Mail Platform

Debian 13 amd64向けメールサーバーの導入・管理・署名付き更新コードです。Roundcube、クライアント証明書、送信量制限、転送・Sieve、監視、ウイルス・添付制御を組み込みます。

## Rspamd symbols.cache修正（ソース公開）

Debian Rspamd 3.12.1-1向けの保存修正を追加しました。
[修正パッチ・ソース準備・ビルド／適用手順](mail-platform/third-party/rspamd/README.md)
と[ライセンス・変更表示](mail-platform/third-party/rspamd/NOTICE.md)を参照してください。
既存の署名付きv0.4.0資材は変更していません。v0.4.0のインストーラー・更新器は
このパッチを自動適用しません。ソースの反映と新しいバイナリReleaseは別工程です。

## 0.4.0

[署名付きReleaseと配布資材](https://github.com/ken-misystem/mail-server-admin/releases/tag/v0.4.0)

専用WSL Debian 13で、最新版一式の新規導入・初期ログイン・仮想パスキー登録・明示公開、実0.3.0からの移行、故障時の自動復旧を確認しました。メール・UIDL・UIDVALIDITY・DB・台帳・資格情報の保全を確認しています。実メール試験送信は行っていません。

同梱INSTALLATION.mdの「対応版と配布状況」は公開準備時点の記録です。0.4.0の公開状態と最新版一式の検証結果は本案内およびRelease notesを参照してください。実ACME外部API、実VPSの外部経路、物理認証器、全メーラーの実接続はこの検証に含めていません。

## 新規導入

専用の空Debian 13 amd64とsystemdを使用します。署名とSHA256を確認し、サイト設定、私有kit、TLS/CA、バックアップを準備してください。署名公開鍵の信頼は別経路でも確認してください。

- [導入環境・手順](mail-platform/INSTALLATION.md)
- [初期ログインと公開制御](mail-platform/INITIAL_SETUP.md)
- [証明書の取得・更新・CA世代](mail-platform/CERTIFICATES.md)
- [native資材の取得・現地build](mail-platform/NATIVE_ASSETS.md)

環境チェックを最初に実行します。既存アプリ、ポート、配置先、所有者・権限の競合を検出すると停止します。初期UIはloopback限定で、期限付き初期資格情報とパスキー登録後に管理者が明示公開します。VPS側の公開ポートも、その判断後に設定してください。

## 更新

手動承認と自動更新を選択できます。更新器は署名、対象版、所有ファイル、構成を照合して適用し、障害時には既知変更だけを条件付き復旧します。

0.4.0の初回移行用Releaseは、固定blueprintとDovecot ABIが一致する0.3.0が対象です。旧0.1.xからの直接更新は未検証です。登録済みweb・Roundcube・policyのformat 2世代更新はサイト構成hashに結び付く資材を使用します。今回の初回移行はformat 1です。

[更新・署名確認](mail-platform/RELEASE.md)・[検証範囲](mail-platform/VALIDATION.md)

## ライセンス

独自コードはMIT、著作権表示はMI-SYSTEMです。第三者製コードには各元ライセンスを保持します。旧Roundcube修正patchはGPLv3以降、ClamAVはGPLv2、Dovecot/PigeonholeはMIT/LGPL等の各条件を適用します。元の許諾文・変更表示・対応ソースを提供します。

[ライセンス範囲](mail-platform/LICENSING.md)・[第三者一覧](mail-platform/THIRD_PARTY.md)・[配布方式](mail-platform/DISTRIBUTION.md)

既定の構成は原版Roundcubeと独立pluginです。OS packageは導入先APT、ClamAVは公式資材、Dovecotは対応sourceから現地準備します。公式ウイルス定義、私有kit、顧客データ、秘密鍵・資格情報を公開資材に収録しません。
