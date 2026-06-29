# 外部オラクル（正は実装＝直読。要約は置かない）

per-task で全読みせず、値/フォーマット/シーケンスが要るときだけ該当箇所を**狙い撃ち**で読む。

| オラクル | 所在 | 権威範囲（これが正） |
|---|---|---|
| **nrs.exe** | `C:\src\bbs\nrs.exe`（ImageBase 0x400000, x86-32, ASLR有） | ゲーム本体。Ghidra MCP（static_VA）で解析。番地・構造体・分岐の最終真実 |
| **micetools** | `C:\src\micetools\` | RingEdge am*/PCP/keychip/JVS/columba の**クリーンルーム実装＝最低レイヤの正・lift 元**。主要箇所: `src/micetools/dll/drivers/`(columba.c, mxjvs.c, jvs_boards/) / `micekeychip/` / `dummynetwork/` / `lib/am/`(amJvs*.h) / `launcher/`(spawn+inject) |
| **TeknoParrot** | `C:\src\TPBootstrapper\` | BBS 設定値/JVS/起動シーケンスの正。`TeknoParrot.dll` は VMProtect で静的不可＝**挙動観測で裏取り**（cdb / API フック） |
| **RingEdge 純正イメージ v63.01.10** | `C:\src\ringedge_system_63.01.10\` | OS/システム層。`system/`=mx*.exe デーモン（mxkeychip/mxsegaboot/mxnetwork…非パック＝Ghidra 可）、segadriver=Columba/mxjvs/mxsram/mxsmbus/… の実ドライバ名、`update/OSupdate.conf`=ブート手順、`ringmaster_pub.pem` |

## 注意

- **segatools は別世代（Nu/ALLS, x64）**。JVS 実装(board/jvs.c, io3/io4)はあるが RingEdge とは配線が違う＝
  **二次プロトコル参照のみ**。一次は micetools。混同は誤実装を招く。
- micetools/segatools のコードを lift する場合は各**ライセンスを順守**（取込前に確認）。
