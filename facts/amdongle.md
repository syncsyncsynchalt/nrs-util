# amDongle FACTS（co-located）

このサブシステムの事実（アドレス/構造体/RVA）。索引 `_index.md` / 横断知見 `workflow.md`。
confidence: [S]=静的解析 [L]=ライブ実走 [I]=推論 [F]=旧 Frida 計装(履歴・再取得は Ghidra/実走)

---

### dongle 静的パッチ（`src/logic/patches.c`, bind 時適用）

| 種別 | static_VA | Function | 内容 |
|---|---|---|---|
| patchCode | 0x457AF0 | `delete_directory_recursive`(DB名, appdata 再帰削除 FindFirstFile/DeleteFile/RemoveDirectory) | entry→`xor eax,eax; ret 8`（standalone で appdata 削除 skip）。**__thiscall・stack 引数 8B**（call site 0x4579F4 add esp 無し＝callee clean＝`ret 8`）。⚠ bare `ret` は 8B スタック破壊でクラッシュ。発火は `DAT_016014b0==0 && DAT_01601b23!=0 && DAT_016014af==0` のみ（clean boot 非発火） |

amDongleBusy(0x975E00) は amInstall SM を 40102 応答で genuine 完走させ busy を自然に 0 にすることで撤去済み（下記§amInstall）。gap の正体は keychip_server が amInstall(port 40102)の query に正式応答していなかったこと。

---

## amInstall（ゲームイメージ install/verify SM, port 40102/40103）[S][L]

`amDongle_top_level_init`(0x457500) が **ブロッキング init**: `do{ outerSM_tick_dispatcher() }while(state!=7)` ＋
`do{ keychipSM_FSM() }while(!=done)`。両 SM が `amDongleBusy`(0x975E00=ctx[0xc])を待つため、PCP が完走しないと boot hang。
- **async SM** `amDongle7_dispatcher`(0x978450): ctx+0x18 を 2(send FUN_00975f90)→3(recv FUN_00976000)→4(parse FUN_00977d50)→
  …→7(done, ctx[0xc]=0) と駆動。recv が応答を得れば完了、未応答だと busy のまま。
- **wire**: req=`request=<verb>&...`、resp=`response=<verb>&result=success&<fields>`（amNet と同形式・`&`区切り。`result` は文字列 "success"）。
  応答 parse=`FUN_00977d50`("response" キーを ctx+8(req type)別 verb と strcmp)＋`FUN_009765d0`("result"=="success" 必須)。
- **ボートで発行される query（実走 40102 計装で確定）**: query_application_status / query_slot_status(slot=originalf,patchb) /
  check_appdata / query_appdata_status。**install(req type 2)は不発＝40103 不使用**。
- **応答 status の steer（keychip_proto.c, status→数値表は各 processor の strcmp）**:
  - query_slot_status → `complete`（FUN_009767f0: empty0/install1/check2/complete3）= 既インストール。
  - query_application_status → `inactive`（FUN_00976aa0: inactive0/active1）= アプリ未起動。
  - query_appdata_status/check_appdata → **`error`**（FUN_00977050: available4/restored5/unknown0/error-1/needed3/checking1/formatting2）。
    appdata status の唯一の整合解＝3 consumer の交差: ①keychipSM case3 query(ctx+8=0xe)は status∈{0,1,2,3,-1}で gameid 不要に成功
    （4/5 は gameid フィールド必須・無いと "Failed to get appdata status"）②keychipSM case4 は -1 で format 回避・state7-done
    （3=needed/4/5 は format/削除誘発。gameid 一致 appdata_gameid_region_match は EEPROM HISTORY 由来で standalone は不定）
    ③appdata task(ctx+8=0xf, FUN_00977230)は param∉{0,1,2}で terminate（0/1/2 は check_appdata⇄query を無限ループ）。
- 関数名/アドレスの正は Ghidra DB（keychipSM_FSM 0x457910 の flow は state0→…→state7(done)）。

---
