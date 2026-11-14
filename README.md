# MI SYSTEM Mail Platform

Debian 13 amd64向けのメールサーバー配布・更新パッケージ。Postfix、Dovecot、標準Roundcubeと独自プラグイン、管理画面、端末証明書、送信量制限、転送・迷惑メール・ウイルス設定、署名付き更新を組み合わせる。

## 配布状況

2026-11-14時点で、導入・更新バイナリの配布を停止し、ソースとライセンス資料を公開している。0.4.0は署名付きReleaseの再公開準備中である。

以下は0.4.0候補に追加した環境チェック・安全な初期ログインに対応する手順である。これらの実装はローカル候補で検証した。対応する署名付き導入資材の公開後に本手順を使用する。GitHubの現行mainと旧0.1.1には追加前のコードが含まれる。

## 導入する環境

| 項目 | 条件 |
|---|---|
| OS | 専用の空Debian 13、amd64/x86_64 |
| 起動・権限 | systemd、rootの対話端末、Python 3 |
| ネットワーク | サーバーへ割り当てたグローバルIPv4、管理用SSH、APT・公式資材・更新元へのHTTPS接続 |
| ホスト名 | 管理するFQDNとドメイン、ホスト名に一致する有効なTLS証明書 |
| 既存アプリ | メール・Web・DB等の競合を環境チェックで確認 |
| 保存領域 | rootが管理する書込み可能な配置先、メール・DB・AV定義・バックアップの容量 |
| CPU・RAM・disk容量 | 固定の最低必要量は未確定。利用者数・メール保管量・AV利用に合わせて確定する |

空Debian 13.5を専用WSL2内のsystemd-nspawnで起動し、導入・更新・条件付き復旧を検証した。新しい初期設定方式は成功済み工程と追加差分の証拠を組み合わせて確認した。最新版一式の空OSからの単一無中断実行、実VPSの外部経路、物理パスキーは未確認である。

## 導入手順

1. 正式資材の署名・SHA256を確認し、サイト設定を作る。
2. 環境チェックを実行し、既存アプリ・ポート・配置先・権限の競合を解消する。
3. 新サイト用のTLS・CA・native資材をroot専用kitへ準備する。
4. 計画を確認してinstallを実行し、loopback限定の初期管理UIを起動する。
5. 管理用のHTTPS接続経路から初期ログインし、パスキーを登録・認証する。
6. 恒久パスワードへ変更し、rootのpublishで公開する。
7. ドメイン・利用者、VPS/OSのFW、DNS、通知、バックアップを設定する。

以下のコマンドは導入先のrootシェルで、対応する導入archiveを展開したディレクトリーから実行する。site.jsonは導入先の値で作成する。

```sh
python3 -I -S -B install.py check --site site.json \
  --evidence /root/mail-platform-environment-001

python3 -I -S -B install.py plan --site site.json
```

環境チェックは予約TCPポートのIPv4・IPv6・loopback、既存package/unit、専用ユーザー/グループ、配置先・リンク・所有者・書込み権限を確認する。競合時は一覧を返して終了2となる。installにも初期資格情報の発行前と設定変更開始前の確認を組み込んでいる。

初期UIは127.0.0.1:443で待ち受ける。ランダムな初期パスワードを管理端末へ表示し、発行から30分で失効する。パスキー登録・認証後にrootが明示公開する。[導入環境と全手順](mail-platform/INSTALLATION.md)、[初期ログインと公開](mail-platform/INITIAL_SETUP.md)

## 資材・更新・復旧

公式ClamAV資材とDovecot cnfix1の対応ソース・build手順を利用し、導入先のkitへ必要な資材を準備する。独自MITと第三者GPL/LGPL等の許諾文・notice・対応ソースを保持する。[native資材](mail-platform/NATIVE_ASSETS.md)、[ライセンス](mail-platform/LICENSING.md)

署名付き正式Releaseの公開後、管理画面で手動更新・自動更新を選択する。初期値は手動である。更新は署名と内容を検証し、失敗時は既知の変更だけを条件付きで復旧する。導入途中のDB・メール・UIDL・資格情報・履歴は保持する。[配布資材の署名確認](PUBLICATION.md)、[更新手順](mail-platform/RELEASE.md)

## ライセンス

独自コードはMIT License、Copyright (c) 2026 MI-SYSTEM。第三者製コードには元のライセンスとnoticeを適用する。[適用範囲](mail-platform/LICENSING.md)
