# mxmaster — FACTS（co-located）

横断定数 `../ARCH.md` / 索引 repo ルート `FACTS.md`。

mxmaster（foreground process manager, **port 40100**）は **in-game モジュールを持たない**。
`boot/keychip/server/pcpa_server.py` がサーバ側で応答する（micetools `micemaster/callbacks/foreground.c` 相当）。

応答仕様（[F]）: `mxmaster.foreground.getcount=N` → `getcount=N` ＋別行 `count=0`（`code=0` のみだとゲームが
~2 秒で終了）。`foreground.active=?`/`current=?` → `=1`。詳細は `../keychip/FACTS.md` の PCPA 節と pcpa_server。
