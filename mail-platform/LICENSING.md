# ライセンスと配布資材

独自コードにはMIT Licenseを適用する。著作権表示はCopyright (c) 2026 MI-SYSTEMである。許諾条件の全文はLICENSEへ収録した。第三者componentの公開一覧はTHIRD_PARTY.md、取得方法はdistribution-policy.jsonとDISTRIBUTION.mdを参照する。

## 第三者製コード

- Composer依存とPyMySQLは、各配布物に含まれる著作権・許諾・免責表示を保持する。生成済み導入・更新資材のdistribution-inventory.jsonへ版・宣言ライセンス・noticeのhashを収録する。
- Roundcube本体は導入先APTから取得し、元のGPLv3以降とskins/plugins例外を維持する。既定のplugin構成では本体を原版に保ち、独自mail_settingsを標準plugin APIで登録する。独自pluginのMIT全文も同梱する。Roundcubeの公式例外は、本体を参照して関数を呼び出すplugin/skinを本体の改変と扱わない条件を定めている。元のmanagesieve parser/engineの複製は独自pluginへ含めていない。
- 旧構成のSieve修正patchと移行用の逆適用資料はGPLv3以降のまま保持する。正本はthird-party/roundcube/patches、変更者・変更日と修正内容はthird-party/roundcube/NOTICE.mdに記載する。移行先のMI-SYSTEM-MODIFICATIONS.mdには原版へ復帰した状態を記録する。旧patchを収録する配布物にも元GPL全文・著作権・追加許諾を同梱する。
- Dovecot cnfix1の対応source候補には元source、修正patch、build手順、MIT/LGPLと個別例外、PigeonholeとDebianのcopyrightを含む。専用Debian 13で実buildした必要7packageと、その同じ修正treeから生成した対応source5件を配布候補にまとめ、空OSへの実導入を確認した。bit単位の再現buildは未確認である。
- ClamAVの外部runtime資材はnative_assets.pyでGPLv2全文・vendored依存のnotice・対応source提供資料を組み合わせる。公式sourceとRust依存195件の対応・ファイルchecksumを確認する。
- ClamAV定義DBは導入先FreshClamで取得・検証し、私有kitへ採用する。製品コード候補と公開native資材の定義DB収録数は0である。
- DebianのOS packageは導入先のrepositoryから取得する。packageを再配布する場合は、版ごとのcopyrightと対応sourceを確認する。

LICENSE、本文書、THIRD_PARTY.md、DISTRIBUTION.md、distribution-policy.json、Roundcubeの変更表示とLICENSEを導入候補へ収録する。同じ資料と生成inventoryを更新用payloadのusr/local/lib/mail-platform-update/licenses以下へ収録する。

標準構成ではOS packageを導入先repositoryから取得し、ClamAVの公式資材とDovecotの対応sourceから現地kitを準備する。改造版binaryを提供するときは、同版の対応source・patch・build recipe・license/noticeを別資材として対応付ける。実機合否はreadiness.json、検証範囲はINSTALLATION.mdを参照する。

独自コードのMIT適用範囲と、各第三者componentの元ライセンスを維持する。2026-11-13に公式Roundcubeのplugin例外、GNU GPLv3の第5/6/7節、ClamAVのGPLv2表示とunRAR条件を照合した。配布物のnotice・対応sourceの実照合結果は検証報告へ記録する。

- [Roundcube公式ライセンス](https://roundcube.net/license/)
- [GNU GPLv3全文](https://www.gnu.org/licenses/gpl-3.0.html)
- [ClamAV公式ライセンス表示](https://docs.clamav.net/Introduction.html)
- [ClamAVのpackageとRAR対応条件](https://docs.clamav.net/manual/Installing/Packages.html)
