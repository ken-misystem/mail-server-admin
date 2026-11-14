# Roundcube managesieve変更表示

変更者はMI-SYSTEM。転送画面の修正を2026-11-11に適用し、この変更表示を2026-11-13に補完した。

対象はRoundcubeのmanagesieve pluginに含まれる次の2ファイルである。

| ファイル | 変更内容 |
|---|---|
| lib/Roundcube/rcube_sieve_engine.php | 条件配列が省略されたルールの参照処理を補完する |
| lib/Roundcube/rcube_sieve_forward.php | 条件省略ルール・任意項目の処理と、条件配列の型確認を補完する |

元のRoundcube著作権表示、GPL version 3 or later、上流のskins/plugins例外を保持する。この2件の修正と配布patchには同条件を適用する。LICENSEに許諾条件を収録している。

各patch先頭に変更者・変更日・適用ライセンスと差分本体のSHA256を記録する。導入時に同じ文書をmanagesieveのMI-SYSTEM-MODIFICATIONS.mdへ配置する。

PHPの修正処理は、保存済み2026-11-11の修正版と同じである。今回の補完は配布patchの表示と同梱文書を対象とする。

元のGPL全文と追加許諾は製品のlicenses/roundcube/LICENSE、およびthird-party/roundcube/LICENSEを参照する。

[Roundcube公式ライセンス](https://roundcube.net/license/)
