# FACTS — 索引（事実は co-located）

nrs.exe の事実（アドレス/構造体/プロトコル）は**各サブシステムのコードに co-locate** してある。
このファイルは索引のみ。1 サブシステムの作業は当該ディレクトリ閉で完結する（巨大 FACTS 全読み不要）。

confidence 凡例: [F]=Frida確認 [S]=静的解析 [I]=推論

## 横断（全サブシステム共通）
- [boot/ARCH.md](boot/ARCH.md) — バイナリ base / static_VA・va() 規約 / PCP ポート・ワイヤ形式 / 静的ライブラリ / TeknoParrot パッチ

## サブシステム別 FACTS（コードと同階層）
| subsys | facts | boot dir |
|---|---|---|
| amNet（DHCP/NIC/種別） | [boot/mxnetwork/FACTS.md](boot/mxnetwork/FACTS.md) | `boot/mxnetwork/` |
| keychip / PCP | [boot/mxkeychip/FACTS.md](boot/mxkeychip/FACTS.md) | `boot/mxkeychip/` |
| amJvs / amJvsp | [boot/amjvs/FACTS.md](boot/amjvs/FACTS.md) | `boot/amjvs/` |
| amDongle | [boot/amdongle/FACTS.md](boot/amdongle/FACTS.md) | `boot/amdongle/` |
| mx ドライバ層 / amBackup 層（mxsram/mxsmbus + am 層スタック） | [boot/mxdrivers/FACTS.md](boot/mxdrivers/FACTS.md) | `boot/mxdrivers/` |
| amPlatform | [boot/amplatform/FACTS.md](boot/amplatform/FACTS.md) | `boot/amplatform/` |
| amGfetcher | [boot/mxgfetcher/FACTS.md](boot/mxgfetcher/FACTS.md) | `boot/mxgfetcher/` |
| ALL.Net Plus Billing（alpbEx, `patches.json` 0xA065C0） | [boot/ambilling/FACTS.md](boot/ambilling/FACTS.md) | `boot/ambilling/` |
| storage presence（`patches.json` 0x4FDA50） | [boot/mxstorage/FACTS.md](boot/mxstorage/FACTS.md) | `boot/mxstorage/` |
| 周辺デバイス presence 連鎖 | [boot/devices/FACTS.md](boot/devices/FACTS.md) | `boot/devices/` |
| amlib SYSTEM STARTUP | [boot/mxsegaboot/FACTS.md](boot/mxsegaboot/FACTS.md) | `boot/mxsegaboot/` |

## boot 構成・運用
- ロード順 / persistence / va（static_VA）/ network_role → [boot/MANIFEST.json](boot/MANIFEST.json)（boot 構成の単一ソース）
- アドレス表記は全て **static_VA**（一方言）。RVA/runtime_VA は `boot/lib/base.js` の `va()` 内部のみ → [boot/ARCH.md](boot/ARCH.md)
- 全体像・起動コマンド → [boot/README.md](boot/README.md) ／ 規約 → [boot/CONVENTIONS.md](boot/CONVENTIONS.md)
- 逆コンパイル C / xref → Ghidra MCP `mcp__ghidra__decompile_function_by_address`
- 参照実装 → `docs/teknoparrot.md` / `docs/micetools.md` / `docs/bsnk_ringedge.md`
- バグ・アンチパターン → `BUGS.md`
