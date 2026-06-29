# amRtc FACTS（co-located）

横断定数 `../ARCH.md` / 索引 repo ルート `FACTS.md`。

amRtc サーバ時刻を PC ローカル時刻に、`SetServerTime` を無視する（`rtc.js`、persistence=runtime）。
hook: 0x974040（amRtcGetServerTime）/ 0x9742C0（amRtcSetServerTime）。詳細は `rtc.js` のヘッダ参照。
