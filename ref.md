# 外部オラクル（正は実装＝直読。要約は置かない）

per-task で全読みせず、値/フォーマット/シーケンスが要るときだけ該当箇所を**狙い撃ち**で読む。

**権威の階層（食い違ったら上が勝つ）**: ① nrs.exe（ゲーム本体） → ② RingEdge 1 実バイナリ → ③ RingEdge 2 実バイナリ → ④ micetools / TeknoParrot（補助）。
micetools は**クリーンルーム再実装**、TP は**挙動観測**。どちらも RE1/RE2 の純正バイナリと矛盾したら**純正バイナリが正**。

| オラクル | 所在 | 権威範囲（これが正） | 順位 |
|---|---|---|---|
| **nrs.exe** | `C:\src\bbs\nrs.exe`（ImageBase 0x400000, x86-32, ASLR有） | ゲーム本体。Ghidra MCP（static_VA）で解析。番地・構造体・分岐の最終真実 | ① |
| **RingEdge 1 — 純正ドライバ** | `C:\src\RingOSUpdate\common\segadriver\` | **driver 層の正本**。Columba/mxjvs/mxsmbus/mxsuperio/mxhwreset/mxcmos/mxsram/mxparallel/mxusbdevice/Geminifs/kbfilter の**純正 .sys/.inf**（IOCTL/シリアル/レジスタの最終真実）。RE1 固有は `ringedge1\segadriver\`(mxsram) | ② |
| **RingEdge 1 — 純正システム v63.01.10** | `C:\src\ringedge_system_63.01.10\system\` | **system 層の正本**。mx*.exe デーモン（mxkeychip/mxsegaboot/mxnetwork/mxmaster/mxstorage/mxgfetcher/mxgcatcher/mxgdeliver/mxauthdisc/mxinstaller…＝非パック＝Ghidra 可）、`ringmaster_pub.pem`、`update/OSupdate.conf`=ブート手順 | ② |
| **RingEdge 2 イメージ** | `C:\src\RingOSUpdate\ringedge2\`（共通 `common\`、世代固有 `ringedge1\`/`ringedge2\`） | **二次参照**。RE1 と RE2 の差分確認・補強。System32/setting/oemdriver の世代差。`SystemVersion.txt`=00490182 | ③ |
| **micetools** | `C:\src\micetools\` | **補助（クリーンルーム再実装）**。RE1/RE2 純正と矛盾したら純正が正。主要箇所: `src/micetools/dll/drivers/`(columba.c, mxjvs.c, jvs_boards/) / `micekeychip/` / `dummynetwork/` / `lib/am/`(amJvs*.h) / `launcher/`(spawn+inject) | ④ |
| **TeknoParrot** | `C:\src\TPBootstrapper\` | **補助（挙動観測）**。`TeknoParrot.dll` は VMProtect で静的不可＝cdb / API フックで裏取り。BBS 設定値/JVS/起動シーケンスのヒント | ④ |

## 注意

- **segatools は別世代（Nu/ALLS, x64）**。JVS 実装(board/jvs.c, io3/io4)はあるが RingEdge とは配線が違う＝
  **二次プロトコル参照のみ**。一次は RE1 純正ドライバ（`RingOSUpdate\common\segadriver\`）。混同は誤実装を招く。
- micetools/segatools のコードを lift する場合は各**ライセンスを順守**（取込前に確認）。
