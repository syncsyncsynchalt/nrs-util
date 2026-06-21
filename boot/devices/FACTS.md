# 周辺デバイス presence 連鎖 — FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

## Error Scene System & Device-Presence Chain [S+F]

boot 後に居座る「Error NNNN」は**ゲームアプリのエラーシーン**（amlib 09xx 表示とは別経路）。
レンダラ `FUN_006f2730`(RVA 0x2f2730) が記述子を毎フレーム描画。記述子レイアウト:
`+0x00`=amlib errCode / `+0x04`=detail / `+0x0c`=msgPtr / `+0x10`=errNo(表示番号) / `+0x16`=flags(&4=Caution)。

**device-presence 連鎖**: errCode→errNo→fix の対応は `../patches.json`（各行 note に errNo/state）。発生源関数は
`FUN_0089a010` state2(IC Card)/state3(Touch)/state6(Network)＝`../mxsegaboot/FACTS.md`。1つ満たすと次の
デバイスエラーへ前進（実証順 1000→5101→951→5501→8005）。HLSM は全工程 attract 到達済み。
ネットワークメッセージ: `0xbd02c4` "Network timeout error (DNS-WAN)" / `0xbd0304` "Network type error (WAN)"。

**エラーメッセージテーブル**(連続, pointer table 経由で直接 xref 不可):
`0xbd0374` IC Card R/W / `0xbd038c` Touch Panel / `0xbd03a4` USB Device / `0xbd041c` Keychip /
`0xbd0464` Game Program on Storage / `0xbd0518` Sound Function / `0xbd0534` Graphic Function。

### USB Device (951) = USB JVS I/Oボード の連鎖 [S]
- `FUN_00679de0` 末尾: `DAT_016b88dc < 1`(I/Oボード未検出)→ `iVar2=-0x70(-112)` →
  `if(1<DAT_016b6ffc && DAT_016b7000==0) DAT_016b7000=iVar2` / `if(DAT_016b8670!=0 && DAT_016b7000==0) DAT_016b7000=DAT_016b8670(jvs_error_state)`。
- `FUN_006f0ad0`: `switch(DAT_016b7000)` default → `if(DAT_016b8b50!=8) DAT_016f5af0=0xf`。
- **適用 patch**: `0x6F0B80`（`DAT_016f5af0=0xf` の imm `0F→00`。USB I/O board errCode 無効化＝Error 951 non-fatal）。
  正は `../patches.json`（subsys=devices）。
- 回避: `DAT_016b88dc>=1`(+ `DAT_016b88e0<=1 && DAT_016b88e4==1`) かつ `DAT_016b8670==0`、または `DAT_016b8b50==8`。
  `DAT_016014a3!=0` でも skip するが mxkeychip/dongle 派生(`FUN_00459220/459460`)なので force 非推奨。
