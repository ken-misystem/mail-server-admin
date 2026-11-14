# 配布と現地での準備

独自コードの許諾条件はMIT。第三者ソフトウェア・修正はTHIRD_PARTY.mdと各noticeに記載した条件を適用する。

## 標準の配布資材

- 新規導入候補はbuild.pyで生成する。既定は標準Roundcube＋独自pluginの構成。独自コード、ライセンスを保持したvendor依存、旧Roundcube修正patchと移行資料、変更表示とライセンス一覧を収録する。
- 更新候補はrelease_assets.py prepareで生成する。distribution-inventory.jsonは署名対象payloadにも収録し、外部確認用の一覧と同じbytesを使う。
- distribution-policy.jsonに各componentの取得方法を記録する。OS service packageは導入先APTから取得する。
- ClamAVは公式の版・hashをnative-assets-lock.jsonで照合して取得し、native_assets.pyで導入先kitへ準備する。
- cnfix1 Dovecot/Pigeonholeは対応sourceとDebian build recipeを使って導入先用packageを準備し、kitのdovecot_packagesへ登録する。

現行installerのpackages工程は、OS repositoryのpackageと、用意したcnfix1 packageを導入する。ClamAV runtime・公式定義・TLS等は私有kitから採用する。初期のkit作成と署名済み公式資材の取得方法はINSTALLATION.mdとNATIVE_ASSETS.mdを参照する。

## 改造版binary・offline資材を提供する場合

改造版の提供はcomponentごとに行う。binary・対応source・patch・build recipe・license/noticeを同じ版で対応付け、size/SHA256と配布経路を記録する。ClamAVのunRAR等の個別条件も保持する。

native_assets.pyのruntime生成物は現地kitの準備にも利用する。これを公開資材へ採用するときは対応sourceと配布条件を再確認し、公開する資材を本人確認で確定する。

## ライセンス表示の補完

third-party/roundcube/patchesの先頭に変更者・日付・GPL条件と差分本体hashを記載する。NOTICE.mdとGPL全文を同梱し、導入時にmanagesieveへ変更表示文書を配置する。既存PHP修正の内容は保存済み版と一致させる。

既定のplugin構成は元のmanagesieveを有効化せず、独自mail_settingsの転送・filter・休暇応答を使う。既知の本体修正は原版へ戻し、PHPの実bytesとOS packageの原版を照合する。旧構成を選ぶ場合はlegacyを明示し、旧修正と元GPLの表示を保持する。

## 再公開の確認

生成inventory・同梱notice・対応sourceの入手先とhashを照合し、変更した工程の新規検証を行う。再公開とGitHub pushは本人の直前確認後に実施する。
