# 空Debian 13での受入れ確認手順

## 現在の条件

専用WSLのDebian 13 amd64で受入れ検証を完了した。新たな導入先では、対象ホスト・サイト情報・新規私有kit・署名鍵/信頼公開鍵を確定してから実行する。対象と工程、作成資源、サービスへの影響、復旧方法を確認して承認を記録する。

専用WSLの空Debian 13で0.2.4全体のOS/DB/service導入・管理者認証・通常更新・条件付き復旧を確認した。0.3.0はSieve文書GUI・認証画面の補完・公開コード差分の確認を追加し、必要な新規検証と実更新器の追加ファイル配置・復旧・状態保全を確認した。保存済みの合格証拠を再利用し、元の失敗記録も保持する。通常更新の配布条件とformat 2の追加検証条件はRELEASE.mdを参照する。

## 準備と導入

1. site.example.json・kit.example.jsonから導入先専用のsite.jsonと私有kitを準備する。TLS/CA/issuer、独自Dovecot7package、native guard、AV runtime/公式定義、信頼する署名公開鍵、Release取得用資格情報を確認する。
2. hostname・Debian版・architecture・空構成・同名DB/OS利用者の不存在・空き容量を保存する。候補archiveのhashを別接続で読戻す。
3. install.py planでpackage・unit・工程を保存する。INSTALLATION.mdに示すinstall --applyで、新規root専用証拠領域を指定して実導入する。管理者パスワードは端末から非表示入力する。
4. 導入結果・全コマンドの実終了値/原出力、DB/grant metadata、UID/GID・capability、専用service/socket、導入したunitと監視一覧・自然更新・OOM、所有receiptを照合する。保存済みの通常構成では55unitを確認した。
5. ログイン・初回パスキー登録・管理画面・更新画面の権限を実ブラウザーで確認する。サイト固有の秘密値は結果へ転記しない。

## 更新と復旧

1. 同じ導入から得たformat 2 receipt・現在版・現在のcode/unit/hash/属性を保存する。
2. 検証用の新版を同一リポジトリから生成し、版に対応するupdate-contractへ対象unitを記載する。設定/schema/証明書runtimeが変わる場合は専用migration hookを用意する。
3. 手動モードで署名・版・hash・peer UIDを確認し、plan→stage→activate→healthを実行する。管理画面表示、実service保護下の動作、自然周期、installed版とreceiptの一致を記録する。
4. 次の検証版でhealth失敗を注入し、既知code/unit/版の条件付き復旧と、メール・UIDL・台帳・履歴・DB資源・資格情報の保持を確認する。検証用データだけを使用する。
5. 未知ファイル変更・処理結果不明を注入し、held・自動再試行なし・原出力保存を確認する。手動モードと自動モードの切替えを実管理権限で確認する。

## 結果の採用

独立読戻し・評価が終わった項目だけをreadiness.jsonへ反映する。導入成功と更新/復旧成功、実認証画面、Dovecotの互換/配布確認、第三者配布条件、本番署名鍵の準備はそれぞれ証拠を記録する。正式Releaseの公開前に対象版と3assetのhashを提示して確認する。
