# 配布資材の確認

公開鍵は別経路でSHA256とfingerprintを照合してから採用する。

```sh
sha256sum release-public-key.pub
openssl pkey -pubin -in release-public-key.pub -outform DER | openssl dgst -sha256 -binary | openssl base64 -A
```

public key SHA256は`6adf5e38d694aa4b16c74c28e50bb197e4d617035b39e03aaad8e7d39e973e5e`。

`publication.json`はUTF-8/ASCIIのcanonical JSONである。`publication.sig`は同文書に対するEd25519署名のbase64表現である。

```sh
openssl base64 -d -A -in publication.sig -out publication.sig.bin
openssl pkeyutl -verify -rawin -pubin -inkey release-public-key.pub \
  -in publication.json -sigfile publication.sig.bin
```

署名確認後、publication.jsonのassetsにある各ファイルのsha256・bytesをダウンロードした実物と照合する。更新workerはさらにrelease.json・release.sig・更新archive内のmanifestと各payloadを検証する。

新規サイトでのCA/issuer、TLS、DNS、通知先とバックアップは導入先の手順で準備する。詳細は導入archive内のINSTALLATION.mdを参照する。
