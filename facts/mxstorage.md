# mxstorage FACTS（co-located）

mxstorage.exe（ストレージ管理 / TrueCrypt・geminifs マウント）相当。索引 `_index.md` / 横断知見 `workflow.md`。confidence: [S]=静的 [L]=実走 [I]=推論。

## 現状（stub）。実装 `src/logic/patches.c`
| static_VA | 内容 |
|---|---|
| 0x4FDA50 | `FUN_004fda50`(is-DVD-boot-mode predicate) → 0(非DVD/storage OK) 固定。SYSTEM STARTUP state5 / Error 913 "Game Program Not Found on Storage Device" 回避 |

`DAT_01696ad8`(startup mode)が 1/2(DVD/storage-boot)だと state5 sub-1 で `param+0x1c=0xc` → error。nrs.exe を直接
起動（DVD/HDD ゲームイメージ無し）するため DVD-mode probe が失敗する。0 固定＝「非 DVD standalone」で実際の
起動形態と一致。`FUN_004fda50` は 7 call site の共有述語（`FUN_00701800`/`FUN_0072af40`/`FUN_0089a010` state5/
`FUN_0089e240`）。DVD-mode 固有経路が要るなら要見直し。
