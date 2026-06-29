/* status.h — host 内集約ステータス。
 * host_log の全イベントを観測し nrsedge.status.json を 1 ショット読取可能な形で常時更新する。
 * abi.h 不変・logic.dll 無改変（host_log が全ログの単一通過点であることを利用）。 */
#pragma once

/* host_log() から全行が渡る。level=("info"|"warn"|"error"…), json_line=m ペイロード(内側 JSON)。 */
void status_observe(const char *level, const char *json_line);
