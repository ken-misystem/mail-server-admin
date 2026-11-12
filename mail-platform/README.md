# Mail platform — 同一リポジトリで管理する配布候補

状態は専用Debian 13で導入・更新・復旧を検証済みの配布候補である。正式署名とGitHub公開は本人確認後に行う。検証結果と導入先の確認項目はVALIDATION.mdを参照する。

## ソースと更新の関係

開発元は既存の Yaruani/mail-server-admin、事業用の公開・更新先は ken-misystem/mail-server-admin とする。公開名義はMI SYSTEMである。build.pyはsource-catalog.jsonに登録した開発元の現行ソースを毎回直接読む。開発元を修正し、build・検証・署名した資材を事業用リポジトリへ公開する。履歴・診断・試験専用ファイルは公開資材から除外する。

- provider=repository：同一repo内の登録ファイルを読む。payload内のスナップショットより常に優先する。
- provider=generated：同一repoの既存生成処理から作る。旧成功試験は実行しない。入力と証拠の整合が崩れた場合、古いコードを黙って配布せずbuildを停止する。
- provider=package：このディレクトリの新規実装・blueprint等が参照元。framework/とui/を編集する。payloadは配布候補とoffline依存cache。
- vendor.tmpがない環境では、保存済み依存cacheをcomposer.lockの完全一致時だけ利用する。lock更新時は依存を再構築して候補を更新する。

開発元へのcommit後、事業用リポジトリに検証済みの署名付き正式Releaseを公開すると更新機構が検出する。管理画面で「正式リリースを自動更新」「通知を確認して手動で更新」を切替える。

## 候補の生成

```powershell
python -B mail-platform/build.py --repository-root . --version 0.1.0 --output ./mail-platform-dist/0.1.0-candidate
```

現在の成果物は source-candidate.tar.gz とbuild-result.json。秘密鍵、パスワード、Webhook、実DB行、メール、UIDL、取得履歴は含めない。既存の独自コード・管理画面・独自Roundcube拡張・DB構造・最小権限metadata・systemdのblueprintを含む。

```sh
# 候補の読取り確認だけ。既存の/etcやサービスへ適用しない。
python3 install.py plan --site site.example.json
python3 install.py stage --site site.example.json --output ./bound-candidate
```

site.example.jsonは合成値。サーバー名・ドメイン・IP・通知先を検証して置き換え、内部コードpinも再計算する。現行ken専用POP/旧XMail残着回収は移行専用であり、新規導入時に有効化しない。

## 更新候補の動作

GitHub Releases APIで正式版だけを検出。Ed25519署名、archive/manifest/payloadのSHA256、パス・型・展開量を確認。バージョンの巻戻し、任意URL、リンク付きarchive、未署名/不完全Releaseを拒否する。信頼する公開鍵は初期導入時に別経路で固定し、同じReleaseから自動採用しない。

自動/手動の設定は版付きCASで保存。管理画面はsystemAdmin＋既存パスキー確認＋CSRF＋期限付きnonce＋rate limitを使用。非root PHPからの命令は固定Unix操作だけで、shell/URL/パスを受け付けない。root brokerは固定peer UIDだけを許可する。

更新はplan→stage→activate→health。状態と取引履歴をfsync保存し、health失敗はrollback。復旧不能/終了不明は保留して再試行しない。同じ失敗版を自動再実行しない。手動待機中は検証済みcacheを再利用し、15分ごとの再downloadを避ける。実データ領域はreleaseと分離し、DBの破壊的migrationを自動復旧で巻き戻さない。

正式配布時の固定asset名は mail-platform.tar.gz / release.json / release.sig。現候補は install_ready=false のため自動適用機構も拒否する。本番署名用の暗号化Ed25519鍵は生成・公開署名証跡の独立検証まで完了した。信頼する公開鍵は導入時の別経路で照合する。

## 未完了・適用前の必須条件

readiness.jsonとINSTALLATION.mdを参照。基本設定・証明書actor5設定・同一repo由来の依存組立て、OS package・専用OS利用者・DB・配置・サービスの新規導入adapterを実装した。installの入口は明示的な--apply、私有kit、取引ごとの新規証拠領域、端末での管理者パスワード入力を要求する。設定復旧はCASで行い、DB・メール・履歴・秘密を保持する。

空Debian13での実導入・全service保護下の実行、認証付き画面、実サービスでのupgrade/rollback統合は残る。更新hookは実装した。現候補はinstall_ready=falseを維持する。

独自コードのライセンスはMIT、著作権表示はMI-SYSTEMである。LICENSEとLICENSING.mdに全文と第三者製コードの配布条件を収録した。

## 2026-11-12の追加実装

本番で確認済みのログ日時解析・POP worker取得予算・公開索引修正、Roundcubeのタブ版アプリ設定ヘルプとFairEmailのPOP案内訂正を収録した。source-patches.jsonは現在の登録元ソースへ差分を適用する。既に反映済みなら再適用せず、前提が一致しなければbuildを停止する。

更新用payload/installer.pyはplan・stage・activate・health・rollbackを実装する。初回導入時に所有ファイルとunitのhash/属性を記録し、更新時に照合する。取引ごとに操作と原出力を保存し、未知差分・実行結果不明は保留する。親処理の版記録失敗時にはコードと版記録の両方を条件付きで復旧する。

更新候補には版ごとのupdate-contract.jsonを含める。build.pyの--update-contractで指定し、停止・再開・reload・健康確認の対象を明示する。現在のhookは既存schema・設定blueprint・証明書runtimeを維持するコード更新を扱う。DB/設定変更、unit追加/削除、証明書runtime変更には専用migration hookと検証が必要である。

以前のローカル/非root検証証拠を再利用し、空Debian13での通常導入、管理画面、実root更新hookの適用・条件付き復旧・未知差分保留を確認した。結果と各記録のhashは配布準備側のwsl-validation-v1/REPORT.mdおよびFINAL_ASSESSMENT.jsonに保存した。

現行Dovecotはcnfix1独自修正版。標準Debian版への置換は互換扱いしない。対応source/patchからの実build・実導入・依存版/noticeを確認した。bit単位の再現buildは未確認である。Roundcube1.6.20の転送エラー修正patchも保持する。core更新時は適用元の版・hashを再照合する。

WSL内の空Debian13で実導入と更新/復旧、実ブラウザーで管理者ログインと更新方式変更を確認した。更新配信元は専用HTTPS fixture、署名は検証鍵、パスキーは仮想認証器を使用した。実メール送信は0件である。実VPS・実GitHub・物理認証器の確認は導入先で実施する。

## 配布資材の操作入口

release_assets.pyのplan・prepare・sign・verifyで、固定assetの生成・暗号化鍵による署名・公開鍵での独立確認を行う。操作はRELEASE.mdを参照する。候補を合成鍵で署名してもinstall_ready=falseを保持する。必須検証欄の欠落時も正式資材の生成・署名を保留する。

distribution-inventory.jsonへ同梱Composer依存の宣言ライセンス・版・noticeのhashを保存する。今回確認した58種類・116配置は、全配置に宣言とnoticeがある。Dovecot/ClamAVの対応sourceとnoticeを配布資材へ収録し、空OSで実起動を確認した。

native_assets.pyとnative-assets-lock.jsonでClamAV runtime・対応source・noticeを版固定で組み立てる。公式sourceのRust依存195件を検査し、Dovecot source候補と同時配布用のarchiveへまとめる。導入先kitへの採用と未実施の実環境確認はNATIVE_ASSETS.mdを参照する。

## 運用境界

本番への導入、既存サービスの停止/reload/restart、新しい秘密の配置、正式Release公開、GitHub pushは別途対象と内容を確定して承認を受ける。Private repoのActionsは変更・実行しない。正式リリースはローカル/承認済み検証サーバーで検証して作成する。

APIの参照：GitHub公式 https://docs.github.com/en/rest/releases/releases 。第三者依存のLICENSEはpayload内に保持。
