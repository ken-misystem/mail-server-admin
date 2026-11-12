# 配布資材の生成と署名

更新モードは管理画面でmanual/automaticを選択する。正式な署名付きReleaseを公開すると検出対象になる。同じリポジトリ内の登録元ソースから資材を生成する。

配布生成コマンドはリポジトリ内のmail-platformから実行する。新規導入用archiveはbuild.pyで生成し、操作入口はinstall.pyである。固定3assetは稼働中サーバーのコード更新用である。公開時は新規導入archiveも同じReleaseへ添付する。

## 事前確認

```sh
python3 -B mail-platform/release_assets.py plan
```

readiness.jsonの未完了項目を表示する。空Debian 13での導入・全サービス更新/復旧・実認証画面・専用Dovecot互換/配布確認・第三者配布条件の確認・本番署名鍵の準備を記録する。readiness.jsonの実検証項目は完了した。正式署名前の資材をprepareで作成し、署名・公開は本人確認後に行う。

## 候補を生成

```sh
python3 -B mail-platform/release_assets.py prepare \
  --repository-root . --version 0.1.1 \
  --update-contract mail-platform/update-contract.example.json \
  --output ./mail-platform-dist/update-0.1.1-candidate
```

mail-platform.tar.gz、release.json、prepare-result.json、distribution-inventory.jsonを新規領域へ保存する。候補のinstall_readyはfalseである。署名前のarchive/metadata/manifestを読戻して照合する。

update-contractの版、停止/再開/reload、健康確認の対象はReleaseの実変更に合わせて指定する。現在のコード更新hookはschema・設定blueprint・証明書runtimeを維持する。DB/設定変更、unit追加/削除、証明書runtime変更には専用migration hookと適用/復旧検証が必要である。

PHPまたはincファイルを変更するReleaseでは、php8.4-fpm.serviceをstopとstartの両方へ含める。planは指定漏れを拒否する。旧workerの終了後にコードを切り替え、起動後に健康確認する。停止中はRoundcubeと管理画面の利用が中断する。管理画面のコンテナーcacheはBUNDLE_MANIFEST.jsonのhash別に生成する。

## 正式版を生成

すべての実検証と配布確認が完了しreadinessを証拠付きで更新した後、prepareへ--install-readyを追加して別の新規領域へ生成する。未完了項目があればソース読取り・生成前に終了する。

## 署名と独立確認

```sh
python3 -B mail-platform/release_assets.py sign \
  --directory ./mail-platform-dist/update-0.1.1 \
  --key /offline/mail-platform-signing-encrypted.key \
  --public-key /trusted/mail-platform-release-public.pem

python3 -B mail-platform/release_assets.py verify \
  --directory ./mail-platform-dist/update-0.1.1 \
  --public-key /trusted/mail-platform-release-public.pem
```

署名鍵はパスフレーズ付きPKCS8 Ed25519鍵を使用する。パスフレーズは非表示入力からOpenSSLの標準入力へ渡し、コマンド引数・ファイル・結果記録へ保存しない。公開鍵は別経路で信頼を固定する。署名検証が成功した場合だけrelease.sigを保存する。

合成鍵で候補を検証する場合はsignに--candidateを明示する。候補は署名後もinstall_ready=falseであり、更新workerは適用を拒否する。検証用秘密鍵は一時領域で管理し、検証終了後に破棄する。

## 公開と運用

開発元Yaruani/mail-server-adminからbuildした資材を、MI SYSTEM名義のken-misystem/mail-server-adminへv0.1.1形式の正式Releaseと固定3assetとして配置する。asset名はmail-platform.tar.gz、release.json、release.sigである。公開用ソースにはexport_product.pyが出した製品フォルダーを採用する。リポジトリ作成、push、Release公開、本番適用は承認した対象・工程で行う。GitHub Actionsによるbuild/テストは使用しない。

新規導入のupdate-source.jsonはken-misystem/mail-server-adminを参照する。既存導入先の更新元は保存済み設定を引き継ぐ。更新元の切替えは、公開リポジトリと取得権限を確認し、導入先の変更承認を得てから行う。

更新は署名/hash/版を照合し、plan→stage→activate→healthを実行する。失敗時は既知変更だけを条件付きで復旧し、メール・UIDL・台帳・履歴・追加DB資源・資格情報を保持する。操作結果不明や未知差分はheldとして保存し、同じ版を自動再実行しない。

distribution-inventory.jsonは同梱Composer packageの宣言ライセンス・版・noticeファイルhashを列挙する。これは配布可否の法的判定を含まない。Dovecot独自修正版とClamAVは、実導入済みのbinary/source対応資料を同時配布する。

native_assets.pyで作成したClamAV runtime資材を配布する場合は、対応するmail-platform-native-sources.tar.gzと版/hashを同じReleaseへ付ける。元のsource・署名・全notice・Dovecot source候補を保持する。NATIVE_ASSETS.mdとnative-materials-result.jsonで対応を確認する。定義DBと導入先の私有kitは現地で準備する。
