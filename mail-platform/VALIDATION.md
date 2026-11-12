# Debian 13での導入・更新検証

2026-11-12。専用WSL2 MailPlatform-Debian13内の空Debian 13.5 amd64をsystemd-nspawnで起動して確認した。

| 工程 | 結果 |
|---|---|
| 通常インストーラーによるAPT・DB・利用者・設定・サービス導入 | complete、296.81秒 |
| サイト別host正規表現、実UID/GID、5証明書actor | 合格、全capabilityゼロ |
| Dovecot cnfix1 | 必要7packageを実build・導入、同じtreeのsource5件を同梱 |
| ClamAV 1.4.6 | 非root、公式定義ロード、全capabilityゼロ、OOM0 |
| 実Chromium管理画面 | パスワード＋仮想WebAuthn、手動/自動設定保存・予約が成功 |
| 実署名更新hook | 手動0.1.9、自動0.1.10、監視差分0.1.17が成功 |
| 健康確認失敗 | 0.1.15から旧コードへ条件付き復旧 |
| 未知差分 | 0.1.16でheld、原証拠を保存して既知fixtureだけを解決後に実復旧 |
| 状態保持 | 合成メール/UIDL/履歴、実DB設定・台帳・資格情報hash・受付履歴が一致 |
| 空GitHub token | 実LoadCredential・厳格なHTTPSで匿名no_releaseを確認 |
| 最終監視 | 収集・observer・無効通知workerが終了0、主要service稼働・queue0・OOM0 |

更新元はローカルHTTPSのGitHub API fixtureと検証用署名鍵である。本番署名鍵の秘密値は使用していない。初回の実管理画面操作を保存し、仮想認証器のidle切断後の最終監視更新予約にはmailadminの固定Unix要求を使用した。

7日間の合成TLS証明書は既存の期限警告期間内にあるため、tls_expiringとhealth unit終了2を記録した。期限閾値は維持した。新サイトのバックアップは未設定と表示し、旧サイトの退避成功を流用しない。

実VPSのkernel/起動・外部FW・公開DNS/配送経路、実GitHub上の資材認証、物理パスキー、各メーラーの接続は導入先で確認する。Dovecotのbit単位の再現buildは未確認である。新規サイト用のTLS/CA・秘密・DNS・通知・バックアップ設定はINSTALLATION.mdに従う。

元のFAIL・stderr・途中状態・条件付き復旧記録を保持した。入口templateの修正をcache側へ書いた一度の誤りを訂正し、配布元とarchiveの実バイトを照合した。修正候補の通常導入は20回目に完了し、その後の変更は新規差分として確認した。合格済みの独立suiteは保存証拠を再利用した。

正式配布では、固定3更新assetに加え、ClamAV runtimeと対応source、Dovecot binary/source一式を同じReleaseへ添付する。独自コードはMIT、Copyright (c) 2026 MI-SYSTEM。第三者の元ライセンスとnoticeを保持する。
