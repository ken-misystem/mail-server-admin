# MI SYSTEM Mail Platform

Debian 13 amd64向けのメールサーバー配布・更新パッケージ。

Postfix、Dovecot、Roundcube、管理画面、端末証明書、送信量制限、転送・迷惑メール・ウイルス設定、署名付き更新を組み合わせる。更新方法は管理画面で手動と自動を選択できる。

## 新規導入

[Releases](https://github.com/ken-misystem/mail-server-admin/releases)から新規導入用の`mail-platform-install-0.1.1.tar.gz`を取得し、展開後の`INSTALLATION.md`に従う。空のDebian 13 amd64、root権限、新サイト用のTLS/CA・秘密資材・DNS等の準備を必要とする。kitの秘密値は導入先で用意する。

```sh
python3 -I -S -B install.py plan --site site.json
sudo python3 -I -S -B install.py install --site site.json \
  --kit /root/mail-platform-kit --evidence /root/mail-platform-install-001 \
  --administrator-email admin@example.test --resolver 1.1.1.1 --apply
```

初期更新モードは手動である。署名付き正式Releaseの更新を管理画面で予約できる。

## 資材と署名

`mail-platform.tar.gz`、`release.json`、`release.sig`は稼働中サーバー向け更新資材である。`publication.json`と`publication.sig`は同時配布する導入・更新・ネイティブ資材のSHA256とサイズを署名する。

公開鍵のSHA256は`6adf5e38d694aa4b16c74c28e50bb197e4d617035b39e03aaad8e7d39e973e5e`、Ed25519鍵のfingerprintは`SHA256:sbtECTXMQI/EYdYW4YhDpUxI2YT+J8HTuj71RteTX2A`。導入時の信頼する公開鍵は別経路で照合する。検証方法は[PUBLICATION.md](PUBLICATION.md)に記載する。

Dovecot cnfix1のbinary/source一式、ClamAV 1.4.6 runtimeと対応source、元のlicense/noticeを同じReleaseへ添付する。定義DBとサイト用の秘密資材は導入先で取得・管理する。

## 検証範囲

専用WSL2内の空Debian 13.5/systemd-nspawnで通常導入、実管理画面ログイン、署名付き手動/自動更新、故障時復旧、未知差分保留、状態保持を確認した。更新配信には検証用HTTPS API、署名には検証鍵、パスキーには仮想認証器を使用した。

実VPSのkernel/boot・外部FW・公開DNS/配送、物理認証器・各メーラーは導入先で確認する。詳細は[VALIDATION.md](mail-platform/VALIDATION.md)と[導入手順](mail-platform/INSTALLATION.md)を参照する。

## 開発と配布

このリポジトリはMI SYSTEMの公開製品フォルダーとReleaseを管理する。開発元のYaruani/mail-server-adminを修正し、登録済みソースからbuild・検証・署名してここへ公開する。公開製品フォルダーの`payload`には生成前の参照snapshotも含まれる。新規導入にはReleaseの生成済み導入archiveを使用する。

## ライセンス

独自コードはMIT License、Copyright (c) 2026 MI-SYSTEM。第三者製コードは各元ライセンスとnoticeを保持する。[適用範囲](mail-platform/LICENSING.md)
