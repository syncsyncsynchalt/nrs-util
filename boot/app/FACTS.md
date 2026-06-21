# app（ゲーム窓/プロセス）— FACTS（co-located）

横断定数 `../ARCH.md` / 索引 repo ルート `FACTS.md`。

- `windowed.js`: フルスクリーン抑止・窓スタイル化（QoL）。
- `exit.js`: 終了/exit 経路フック。
- `no_selfshutdown.js`: ルートシステムシーンの self-shutdown を無力化（patchCode persistent）。
固定 RVA なし（API/エクスポートフック中心）以外は各モジュールのヘッダ参照。

## ルートシーン self-shutdown [S/F]

| static_VA | 内容 |
|---|---|
| 0x6C3F10 | ルートシステムシーンの毎フレーム callback（scene_list_init 0x89D690 が設定） |
| 0x6C3F20 | `je 0x6C3F41`→`jmp` に patch（self-shutdown 無力化、`no_selfshutdown.js`） |
| 0x89E880 | `FUN_0089e880` shutdown 判断（制御フラグ DAT_0227fe6c/fe70&4/DAT_02282a64 を読む） |
| 0x89DF40 | `FUN_0089df40` 無条件 shutdown（DAT_016f5aa0=1） |
| 0x644D40 | メインループ。DAT_016f5aa0!=0 で抜けて ExitProcess |
| 0x16F5AA0 | shutdown flag。0x16F5A9C = shutdown state |

amBackup/eeprom 成功でゲームが実機運用パスに進むと FUN_0089e880 が true→shutdown となるため、
0x6C3F20 の `je`→`jmp` patch で無力化する。詳細は `no_selfshutdown.js` ヘッダ／`mxdrivers/FACTS.md` の ENABLE_EEPROM 節。
