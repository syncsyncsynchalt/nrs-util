# amRtc FACTS（co-located）

横断定数 `../ARCH.md` / 索引 repo ルート `FACTS.md`。

amRtc サーバ時刻を PC ローカル時刻に、`SetServerTime` を無視する（`rtc.js`、persistence=runtime）。
固定 RVA なし（am* エクスポートを名前解決でフック）。詳細は `rtc.js` のヘッダ参照。
