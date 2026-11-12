# ネイティブ資材の配布準備

native_assets.pyは固定SHA256の公式ClamAV 1.4.6 deb、公式source/署名/公開鍵、Dovecot cnfix1 source候補から公開配布用の資材候補を作成する。処理はローカルファイルの検査・archive生成である。

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

## 作成する配布資材

- mail-platform-native-sources.tar.gzにClamAV公式source、署名、公開鍵、Dovecot対応source候補、版/hash、依存一覧と本手順を含める。
- mail-platform-clamav-runtime-candidate.tar.gzに、必要な実行ファイル・共有libraryを通常ファイルとして収録する。同じ内容の入力blobを共用し、kit-fragment.jsonとclamav-runtime-manifest.jsonで配置先を特定する。
- runtimeのTHIRD_PARTY_NOTICES.txtに公式source内のnotice全文を収録する。SOURCE-MATERIALS.jsonに同時配布する対応source archiveの名前・hashを保存する。
- native-materials-result.jsonに結果とhashを保存し、各archiveを全byte読戻して照合する。

runtimeを外部配布する際は、対応するsource archiveを同じReleaseのダウンロード先へ配置し、版とSHA256を併記する。アップロード・正式Release署名・公開は本人確認後に実施する。

## 導入用kitへの組込み

専用の新規作業領域へruntime候補を展開し、kit-fragment.jsonのfilesを導入先の私有kit.jsonへ統合する。既存入力名・配置先の衝突は確認して解消する。完成したkitはroot所有・directory0700・file0600で保管し、INSTALLATION.mdの検査を受ける。

TLS/CA/認証情報・定義DBは導入先で準備する。定義DBは導入先のFreshClamで公式配布元から取得する。新環境での初回取得・公式署名確認・ロード完了を記録してから、definition_main/daily/bytecodeの3入力へ採用する。定義DBのGitHub配布資材収録数は0とする。

Dovecot cnfix1の必要7packageを専用Debian 13の非rootで実buildし、空OSへ導入した。同じ修正treeの対応source5件を、build手順・patch・noticeとともにmail-platform-dovecot-cnfix1-candidate.tar.gzへ収録した。ClamAV 1.4.6は公式定義をロードし、実UID993・全capabilityゼロ・OOM0で起動した。VALIDATION.mdを参照する。

生成時のnative-materials-result.jsonは作成時点の記録を保持する。その後の実導入合格はreadiness.jsonとVALIDATION.mdに記録した。正式公開時にはClamAV runtimeと対応source、Dovecotのbinary/source一式を添付する。

## 一次資料

- ClamAV公式Releaseとsourceを参照する。[ClamAV 1.4.6](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.6)
- Cargoのvendorとchecksum metadataを参照する。[cargo vendor](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html)、[source replacement](https://doc.rust-lang.org/cargo/reference/source-replacement.html)
- 公式定義の取得はFreshClamを使用する。[ClamAV公式FAQ](https://docs.clamav.net/faq/faq-cvd.html)
