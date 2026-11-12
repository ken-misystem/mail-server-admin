# 配布・更新機構

- 開発元はYaruani/mail-server-admin、事業用の公開・更新先はken-misystem/mail-server-admin。元ソースを修正してbuildし、検証・署名済み資材と公開製品フォルダーをMI SYSTEM名義で配置する。
- 参照元はsource-catalog.jsonで特定する。provider=repository/generatedは元ソースを修正してbuildする。framework/とui/が更新機構/更新画面の正本。payloadだけを編集して元ソースと二重管理しない。
- build.pyが出したchanged_sourcesを必ず評価する。古いsnapshotを使ってソース変更を隠さない。vendor cacheはcomposer.lock一致時だけ許可する。
- install_readyの変更には空Debian13での導入・upgrade/rollback、実認証UI、秘密分離・UID/GID・独自Dovecot互換の証拠が必要。現在は候補であり適用しない。
- 顧客設定、DB行、メール、UIDL、通知/取得履歴、秘密鍵、資格情報をGit/Releaseへ追加しない。コードだけに含まれる公開パスも実データとしてコピーしない。
- 既存メール・履歴・schema追加資源を削除/巻戻ししない。結果不明は停止し、再実行で確認しない。
- GitHub Actionsは新設/有効化/手動実行しない。root/server・外部repo操作は利用者承認の範囲を守る。
