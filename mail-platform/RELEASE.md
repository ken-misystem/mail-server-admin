# 配布資材の生成と署名

## 0.4.2の共通修正と更新範囲（公開前候補）

監視のキュー設定ディレクトリ・証明書lineageを環境設定へ分離する。新規導入では入力値から生成し、初回移行では旧collectorの固定COMMANDSから取得する。通常更新は既存のenvironment.jsonを内容・属性・inodeごと保持する。環境設定は公開payloadやコード所有一覧に含めない。

公開0.4.0または0.4.1から0.4.2へ直接更新する。中間版の導入は要求しない。
通常構成と世代登録済み構成を、実際の所有記録・設定・unitで判別する。
世代構成のある環境では既存frontを保持し、管理画面とRoundcubeの新workerへ切り替える。
世代外コードの監視・通知等は関連timer/workerを一時停止して整合させ、元の稼働状態へ戻す。
通常構成では関連PHP-FPM／更新UIの停止・再開中に管理画面とRoundcubeが利用できない。

署名対象の旧Rspamd 3.12.1-1では、設定・依存・実行ファイルを照合して
3.12.1-1+0misystem1へ更新する。修正版が一致する環境は再導入しない。
必要なrestartとcache保存reloadの間はMilter判定接続が一時停止する。
SMTP・IMAP・POP・DBの停止は要求しない。設定・DB・メール・UIDL・履歴・資格情報を保持する。
旧0.3.0から0.4.0への既存移行は従来の検証済み工程を使用し、その後はこの直接更新へ接続する。

新規導入にも同じ修正版debと対応ソースを収録する。Rspamdの2debと対応ソースは
署名済みarchive内で一体として照合する。他native製品の公式取得・現地build方式は維持する。
本番の設定・署名秘密鍵・資格情報は配布しない。[詳細契約](COMMON_UPDATE.md)を参照する。

更新モードは管理画面でmanual/automaticを選択する。正式な署名付きReleaseを公開すると検出対象になる。同じリポジトリ内の登録元ソースから資材を生成する。

配布生成コマンドはリポジトリ内のmail-platformから実行する。新規導入用archiveはbuild.pyで生成し、操作入口はinstall.pyである。固定3assetは稼働中サーバーのコード更新用である。公開時は新規導入archiveも同じReleaseへ添付する。

## 事前確認

```sh
python3 -B mail-platform/release_assets.py plan
```

readiness.jsonの通常更新に必要な未完了項目と、世代切替え方式の検証状態を表示する。空Debian 13での導入・更新/復旧・実認証画面・専用Dovecot互換/配布確認・第三者配布条件・本番署名鍵の準備を記録する。0.4.0は新規導入、旧0.3.0からの初回移行、管理画面・Roundcube・実SQL送信量policyのformat 2更新/復旧と起動時復元を専用WSLで確認した。正式署名前の資材をprepareで作成し、署名・公開は本人確認後に行う。

## 候補を生成

```sh
python3 -B mail-platform/release_assets.py prepare \
  --repository-root . --version 0.4.0 \
  --update-contract /approved/update-contract-0.4.0.json \
  --output ./mail-platform-dist/update-0.4.0-candidate
```

mail-platform.tar.gz、release.json、prepare-result.json、distribution-inventory.json、distribution-plan.jsonを新規領域へ保存する。候補のinstall_readyはfalseである。inventoryは署名対象payloadへ同じbytesで収録する。署名前のarchive/metadata/manifestを読戻して照合する。

update-contractの版、停止/再開/reload、健康確認の対象はReleaseの実変更に合わせて指定する。現在のコード更新hookはschema・設定blueprint・証明書runtimeを維持する。DB/設定変更、unit追加/削除、証明書runtime変更には専用migration hookと適用/復旧検証が必要である。

PHPまたはincファイルを変更するReleaseでは、php8.4-fpm.serviceをstopとstartの両方へ含める。planは指定漏れを拒否する。旧workerの終了後にコードを切り替え、起動後に健康確認する。停止中はRoundcubeと管理画面の利用が中断する。管理画面のコンテナーcacheはBUNDLE_MANIFEST.jsonのhash別に生成する。

この停止指定はformat 1へ適用する。format 2は事前に登録したweb・web-roundcube・policyのstable frontと世代別workerを使う。構成hashを導入先の登録値へ固定し、更新対象の全共用入口を選択する。OS/DB/schema、Postfix/Dovecot、frontと更新基盤の変更は専用の保守移行で扱う。異なる導入先の構成hashを流用しない。

## 旧0.3.0の初回移行

`--sieve-migration-kit`へ、対象Dovecotのconfigured source treeから生成した公開moduleとmetadataを指定する。`--sieve-migration-from`には旧versionとblueprint hashだけを収録したJSONを指定する。NATIVE_ASSETS.mdのsourceとbuild手順を使い、顧客receipt全体や資格情報を配布しない。

初回移行はformat 1の検証済み依存順でDovecot・SMTP関連・policyを停止/再開する。既存Sieve sessionを終了し、native module、管理Sieve設定とpolicy snapshot bindを同じ取引で採用する。既知差分だけを条件付き復旧し、メール・UIDL・台帳・履歴を保持する。世代登録は移行後に`site_enrollment.py plan|apply --payload /verified/payload`で実施する。

公開した旧0.1.xからの直接更新はこの0.3.0移行証拠の対象に含まれない。該当環境は導入先のreceiptと専用移行planを確認してから扱う。

## 正式版を生成

対象方式の実検証と配布確認が完了しreadinessを証拠付きで更新した後、prepareへ--install-readyを追加して別の新規領域へ生成する。通常更新のformat 1は導入・通常更新・復旧の検証結果で判定する。format 2はdelivery_preserving_updates_validated=trueも要求する。対象方式の未完了項目があればソース読取り・生成前に終了する。準備済みarchive内の実契約形式と記録を再照合し、署名時にも同じ方式の条件を確認する。

## 署名と独立確認

```sh
python3 -B mail-platform/release_assets.py sign \
  --directory ./mail-platform-dist/update-0.4.0 \
  --key /offline/mail-platform-signing-encrypted.key \
  --public-key /trusted/mail-platform-release-public.pem

python3 -B mail-platform/release_assets.py verify \
  --directory ./mail-platform-dist/update-0.4.0 \
  --public-key /trusted/mail-platform-release-public.pem
```

署名鍵はパスフレーズ付きPKCS8 Ed25519鍵を使用する。パスフレーズは非表示入力からOpenSSLの標準入力へ渡し、コマンド引数・ファイル・結果記録へ保存しない。公開鍵は別経路で信頼を固定する。署名検証が成功した場合だけrelease.sigを保存する。

合成鍵で候補を検証する場合はsignに--candidateを明示する。候補は署名後もinstall_ready=falseであり、更新workerは適用を拒否する。検証用秘密鍵は一時領域で管理し、検証終了後に破棄する。

## 公開と運用

開発元Yaruani/mail-server-adminからbuildした資材を、MI SYSTEM名義のken-misystem/mail-server-adminへv0.4.0形式の正式Releaseと固定3assetとして配置する。asset名はmail-platform.tar.gz、release.json、release.sigである。公開用ソースにはexport_product.pyが出した製品フォルダーを採用する。リポジトリ作成、push、Release公開、本番適用は承認した対象・工程で行う。GitHub Actionsによるbuild/テストは使用しない。

新規導入のupdate-source.jsonはken-misystem/mail-server-adminを参照する。既存導入先の更新元は保存済み設定を引き継ぐ。更新元の切替えは、公開リポジトリと取得権限を確認し、導入先の変更承認を得てから行う。

更新は署名/hash/版を照合し、plan→stage→activate→healthを実行する。失敗時は既知変更だけを条件付きで復旧し、メール・UIDL・台帳・履歴・追加DB資源・資格情報を保持する。操作結果不明や未知差分はheldとして保存し、同じ版を自動再実行しない。

distribution-inventory.jsonは同梱Composer packageの宣言ライセンス・版・noticeファイルhash、wheel内の許諾文、component別の取得方法を列挙する。公開コードの一覧はTHIRD_PARTY.mdを参照する。distribution-plan.jsonに今回の標準配布物と第三者componentの準備方法を記録する。DISTRIBUTION.mdに標準構成と改造版binaryの別配布手順を記載する。

native_assets.pyで作成したClamAV runtime資材を配布する場合は、対応するmail-platform-native-sources.tar.gzと版/hashを同じReleaseへ付ける。元のsource・署名・全notice・Dovecot source候補を保持する。NATIVE_ASSETS.mdとnative-materials-result.jsonで対応を確認する。定義DBと導入先の私有kitは現地で準備する。

## 0.4.2共通更新候補

通常構成と世代登録済み構成、Rspamdの修正導入を共通更新契約で扱います。
[保持項目・署名資材・復旧条件](COMMON_UPDATE.md)を参照してください。
