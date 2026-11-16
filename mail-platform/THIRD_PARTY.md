# 第三者ソフトウェアと配布範囲

MI-SYSTEM独自コードのライセンスはMIT。第三者ソフトウェアとその修正は以下の元ライセンスを適用する。

| 対象 | 適用条件 | 配布・取得方法 |
|---|---|---|
| Composer依存 | 各packageのMIT、元の著作権・許諾・免責表示 | 公開sourceとnoticeを同梱する。版と配置ごとのhashは生成inventoryへ記録する |
| PyMySQL 1.2.3 | MIT | wheel内のLICENSEとmetadataを保持する |
| Roundcube本体 | GPLv3以降と上流のskins/plugins例外 | 導入先のOS repositoryから取得する |
| Roundcube Sieve修正2件 | GPLv3以降と上流の追加許諾 | third-party/roundcubeのpatch・NOTICE・LICENSEを配布する |
| MI-SYSTEM mail_settings plugin | 独自コードはMIT | 標準plugin APIを使い、managesieveのparserを複製せず配置する |
| PEAR Net_Sieve | BSD系の元許諾 | php-net-sieveをOS repositoryから導入し、元のcopyrightを保持する |
| Dovecot/Pigeonhole cnfix1 | 一部MIT、その他LGPLv2.1と個別条件 | 対応sourceとbuild recipeから導入先用packageを構築する。binary提供時は対応source・noticeを同版で別配布する |
| ClamAV 1.4.6 | GPLv2、vendored依存とunRAR等の個別条件 | 公式資材を取得し、native_assets.pyで現地のkitを準備する。binary提供時は対応source・noticeを同版で別配布する |
| Postfix、MariaDB、Rspamd、Redis、PHP、nginx等のOS package | 導入した版の各ライセンス | OS repositoryから取得する。導入先の/usr/share/doc内のcopyrightを参照する |
| Certbot・ACME・DNS認証plugin | 導入したDebian packageの各ライセンス | OS repositoryから取得する。製品には呼出し・反映処理を収録し、package本体は同梱しない |

製品候補のdistribution-policy.jsonに取得方法と適用範囲を記録する。build.pyは導入候補のルートと更新用payloadのlicenses以下にdistribution-inventory.jsonを生成する。release_assets.pyは同じinventoryを更新資材の外部確認用にも出力する。

ライセンス一覧は宣言metadata・notice・配布形態を記録する。ソースの出所と派生関係の確認は、変更を加えるファイルごとに行う。

既定のplugin構成では、Roundcube本体を原版に保ち、独自mail_settingsを登録する。旧構成のGPL修正patchは移行と復旧の資料として収録し、patch先頭の変更者・日付・GPL表示、NOTICE.mdと全文を保持する。managesieveのMI-SYSTEM-MODIFICATIONS.mdは選択した構成の状態を記録する。

[Roundcube変更表示](third-party/roundcube/NOTICE.md)
# Rspamd cache修正の追加資料

`third-party/rspamd/`にDebian 3.12.1-1用の保存修正パッチ、固定取得元、準備helper、
build手順を追加した。C++ patch/testはApache-2.0を維持し、独自MITには含めない。
元のApache許諾文とDebianのcomponent別copyright一覧を同梱する。
Rspamd全体の依存にはLGPL等も含まれる。詳細は
[変更表示](third-party/rspamd/NOTICE.md)・[適用範囲](third-party/rspamd/README.md)を参照。
今回の追加はソースのみで、署名付きv0.4.0や自動更新資材は変更しない。
