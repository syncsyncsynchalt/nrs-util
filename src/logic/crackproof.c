/* CrackProof(Htsysm) は方針どおり残置（無改変）。実際の残存パッチ（self-shutdown/delete-dir 等）は patches.c。
 * ここは Htsysm を最小無力化する必要が出た場合の予約枠で、現状は未使用の no-op。 */
void crackproof_init(void) { /* no-op（予約） */ }
