# 周辺デバイス presence 連鎖 FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。横断定数は `../ARCH.md`、索引は repo ルート `FACTS.md`。
confidence: [F]=Frida確認 [S]=静的解析 [I]=推論

---

## Error Scene System & Device-Presence Chain [S+F]

boot 後に居座る「Error NNNN」は**ゲームアプリのエラーシーン**（amlib 09xx 表示とは別経路）。
レンダラ `FUN_006f2730`(RVA 0x2f2730) が記述子を毎フレーム描画。記述子レイアウト:
`+0x00`=amlib errCode / `+0x04`=detail / `+0x0c`=msgPtr / `+0x10`=errNo(表示番号) / `+0x16`=flags(&4=Caution)。

**device-presence 連鎖**: errCode→errNo→fix の対応は `./presence.js`（各行 note に errNo/state）。発生源関数は
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
  正は `./presence.js`（subsys=devices）。
- 回避: `DAT_016b88dc>=1`(+ `DAT_016b88e0<=1 && DAT_016b88e4==1`) かつ `DAT_016b8670==0`、または `DAT_016b8b50==8`。
  `DAT_016014a3!=0` でも skip するが mxkeychip/dongle 派生(`FUN_00459220/459460`)なので force 非推奨。

### Dipsw / board index = board-table check (errCode 0xa / 0xb) [S+F]
- **dipsw read** `FUN_0045a0e0`（唯一の writer）: `amDipswReadByte` 経由で byte2/byte3 を読み、
  そこから派生:
  - `byte2` ← `FUN_00984190`（成功時 `*p=3` とハードコード）。`DAT_01601951`＋flag bit 0x1/0x2。
  - `byte3` ← `FUN_00984130`→`FUN_00983bb0(0)`→`FUN_009836e0`（実 dipsw バイト）。`DAT_01601950`＋
    `index = (byte3>>4)&7`（`0x45A18E SHR AL,4; AND AL,7`）＋flag bits（test/service スイッチ群）。
  - flag `DAT_0160194c` bit↔reader: 0x1/0x2=`FUN_0089b230`(入力カウンタ) / 0x4=`FUN_006c3730`(log level) /
    0x8=`FUN_0045a4c0`(タイマ) / **0x20=`amlib_storage_board_check`(errCode 0xb)**。0x80 は unread。
- **board index reader は2つ** — `amlib_storage_board_check`(`FUN_00679cb0`) と `FUN_006c5470`。
- **board-table** `DAT_00b84554` はバイナリ内の静的定数（writer 無し、8×u32）:
  `[FFFFFFFF, 01, 08, 03, 0F, 04, 0A, 10]`。**index 2 のみ値 8（=有効基板コード）**。
- `amlib_storage_board_check`（`FUN_006c3730` が amlib_master_init 後に**無条件呼び出し**、amHm フラグ非依存）:
  `table[index]!=8 && errCode==0` → `DAT_016f5af0=10`(0xa) を `0x00679dae`／
  `DAT_0160194c&0x20 && errCode==0` → `=0xb` を `0x00679dc1`。errCode 0xa を消すと latch race で 0xb が surface。
- `FUN_006c5470`: 同テーブルを `switch`、case 8 以外で `DAT_016f5ac0=0x11/0x1e`。
- スタンドアロンは dipsw ドライバ不在で読み失敗 → bytes garbage → index/flag が不定 → errCode 0xa/0xb が
  画面ラッチ race の種になる。
- **適用 patch**（実基板の clean 値を源流供給）: `0x45A0F5`（byte2 ロード→`MOV CL,3`）＋
  `0x45A0F9`（byte3 ロード→`MOV AL,0x20`）。byte3=0x20 で既存 `SHR/AND` が index 2 を自然算出し
  table[2]=8 を満たす（0xa 解消）＋ bit 0x8(=flag 0x20)=0（0xb 解消）。byte2=3 は実基板値で
  bit 0x1/0x2 を実機同様に供給。両 reader（0xa / 0xb / FUN_006c5470 の 0x11/0x1e）を源流で恒久解消。
  正は `./presence.js`（subsys=devices）。
