# amRtc FACTS（co-located）

索引 `_index.md` / 横断知見 `workflow.md`。

amRtc サーバ時刻を PC ローカル時刻に、`SetServerTime` を無視する。実装 `src/host/gamehook.c`(d_rtc_get)＋`src/logic/api.c`(on_rtc_get, abi v2)。
hook: 0x974040（amRtcGetServerTime, __stdcall longlong(timeStructOut, dstFlagOut), 失敗 -1 → only-on-failure で GetLocalTime フォールバック）/ 0x9742C0（amRtcSetServerTime, 未実装＝cosmetic）。
