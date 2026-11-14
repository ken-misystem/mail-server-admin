# ネイティブ資材の配布準備

本ページは準備中の0.4.0候補に対応する。現在は対応ソース・ライセンス資料を公開し、導入・更新バイナリの配布を停止している。対応する正式資材の公開後、その版に付属する手順と固定hashを使用する。

native_assets.pyは固定SHA256の公式ClamAV 1.4.6 deb、公式source/署名/公開鍵、Dovecot cnfix1 source候補から現地kit用資材を準備する。処理はローカルファイルの検査・archive生成である。取得・配布の標準構成はdistribution-policy.jsonとDISTRIBUTION.mdを参照する。

## 資材の作成

```sh
python3 -B mail-platform/native_assets.py \
  --package ./cache/clamav-1.4.6.linux.x86_64.deb \
  --source ./cache/clamav-1.4.6.tar.gz \
  --source-signature ./cache/clamav-1.4.6.tar.gz.sig \
  --public-key ./cache/talos-public-key.gpg \
  --dovecot-source ./cache/dovecot-cnfix1-corresponding-source-candidate.tar.gz \
  --output ./mail-platform-dist/native-materials-candidate
```

採用する版とhashはnative-assets-lock.jsonで固定する。公式signatureの検証記録と一致する資材を使用する。ClamAV source内のCargo.lockと195依存の対応、vendored sourceのファイルchecksum、各noticeを照合する。

## 作成する資材

- mail-platform-native-sources.tar.gzにClamAV公式source、署名、公開鍵、Dovecot対応source候補、版/hash、依存一覧と本手順を含める。
- mail-platform-clamav-runtime-candidate.tar.gzに、必要な実行ファイル・共有libraryを通常ファイルとして収録する。同じ内容の入力blobを共用し、kit-fragment.jsonとclamav-runtime-manifest.jsonで配置先を特定する。
- runtimeのTHIRD_PARTY_NOTICES.txtに公式source内のnotice全文を収録する。SOURCE-MATERIALS.jsonに同時配布する対応source archiveの名前・hashを保存する。
- native-materials-result.jsonに結果とhashを保存し、各archiveを全byte読戻して照合する。

生成したruntimeは導入先の私有kitへ採用する。runtimeを外部配布する場合は、component別に対応するsource archiveを同じReleaseのダウンロード先へ配置し、版とSHA256を併記する。アップロード・正式Release署名・公開は本人確認後に実施する。

## 導入用kitへの組込み

専用の新規作業領域へruntime候補を展開し、kit-fragment.jsonのfilesを導入先の私有kit.jsonへ統合する。既存入力名・配置先の衝突は確認して解消する。完成したkitはroot所有・directory0700・file0600で保管し、INSTALLATION.mdの検査を受ける。

TLS/CA/認証情報・定義DBは導入先で準備する。定義DBは導入先のFreshClamで公式配布元から取得する。新環境での初回取得・公式署名確認・ロード完了を記録してから、definition_main/daily/bytecodeの3入力へ採用する。定義DBのGitHub配布資材収録数は0とする。

Dovecot cnfix1の必要7packageを専用Debian 13の非rootで実buildし、空OSへ導入した。同じ修正treeの対応source5件を、build手順・patch・noticeとともにmail-platform-dovecot-cnfix1-candidate.tar.gzへ収録した。ClamAV 1.4.6は公式定義をロードし、実UID993・全capabilityゼロ・OOM0で起動した。VALIDATION.mdを参照する。

生成時のnative-materials-result.jsonは作成時点の記録を保持する。その後の実導入合格はreadiness.jsonとVALIDATION.mdに記録した。標準配布は製品コードと対応source・取得/build手順を提供する。ClamAV runtimeまたはDovecot binaryを別途配布する場合は、同版の対応source・notice・build手順を同じ配布先へ添付する。

## Sieveのサーバー側排他module

`native/sieve_session_lock.c`はMIT・MI-SYSTEMの追加コードである。導入先のDovecotと同じconfigured source treeを使う。既存Dovecot/Pigeonholeの元ライセンス・対応source・noticeも保持する。新規導入のkitには次の2入力を追加する。

```sh
python3 -I -S -B payload/usr/local/lib/mail-platform-update/sieve_lock.py build \
  --dovecot-build-tree /private/dovecot-configured-source \
  --source payload/blueprint/native-sources/sieve_session_lock.c \
  --output /private/sieve-lock-kit
```

- `sieve_session_lock`へ生成した`sieve-session-lock.so`を指定する。
- `sieve_session_lock_metadata`へ生成した`sieve-session-lock.json`を指定する。
- 両ファイルの実SHA256を私有kit.jsonへ登録する。root所有0600・単一リンクの入力を使う。

生成記録にはC source、module、Dovecot config.hのSHA256とDovecot ABIを保存する。installerはsource/module pinとamd64 shared ELFを照合し、moduleを`/usr/lib/dovecot/modules/lib90_mail_sieve_session_lock_plugin.so`へ0644で配置する。metadataは`/etc/mail-platform/sieve-lock.json`へ0600で置く。Dovecot自身もplugin ABIを照合する。

実Dovecot 2.4.1・ABI `2.4.ABIv1`で、グローバル`mail_plugins`登録、実PHP、別世代・別名を含む本人単位の排他と終了時の解放を確認した。既存構成への初回採用では、pluginを持たない旧ManageSieveセッションの終了も必要である。0.3.0から0.4.0は固定blueprintと公開moduleを持つ専用移行hookの適用・故障復旧を専用WSLで確認した。RELEASE.mdの初回移行工程を使う。

## 一次資料

- ClamAV公式Releaseとsourceを参照する。[ClamAV 1.4.6](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.6)
- Cargoのvendorとchecksum metadataを参照する。[cargo vendor](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html)、[source replacement](https://doc.rust-lang.org/cargo/reference/source-replacement.html)
- 公式定義の取得はFreshClamを使用する。[ClamAV公式FAQ](https://docs.clamav.net/faq/faq-cvd.html)
