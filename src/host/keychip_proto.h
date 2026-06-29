/* keychip PCP 応答ロジック（純粋・winsock 非依存＝test 可）。keychip_server.c と test から使う。 */
#pragma once
/* 要求 1 行 → 応答 body（"\r\n>" は呼出側が付加）。動的応答は buf に書く。 */
const char *kc_respond(const char *line, char *buf, int cap);
