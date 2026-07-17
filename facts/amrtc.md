# amRtc FACTS（co-located）

索引 `_index.md` / 横断知見 `workflow.md`。

confidence: [S]=静的解析 [L]=ライブ [I]=推論

amRtc サーバ時刻を PC ローカル時刻に、`SetServerTime` を無視する。実装 `src/host/gamehook.c`(d_rtc_get)＋`src/logic/api.c`(on_rtc_get, abi v2)。
hook: [S]
- 0x974040 amRtcGetServerTime `longlong(SYSTEMTIME* out, uint* dstOut)`。失敗時 edx:eax=-1 → only-on-failure で GetLocalTime フォールバック。
- 0x9742C0 amRtcSetServerTime（DB 上は FUN_009742c0 だが内部エラー文字列 "amRtcSetServerTime" で確定）。hook せず放置（get 側で PC 時刻を返すため無害）。
