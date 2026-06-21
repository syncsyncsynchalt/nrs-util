// data/known_names.json (static_VA -> 名前) を起動時に live Ghidra program へ適用し、
// mcp__ghidra__* の出力に我々の名前を表示させる。analyzeHeadless はリネームを永続化しないため、
// これはサーバ起動ごとに実行される（-preScript として、GhidraMCPHeadless.java より前に）。
// known_names.json の形:
//   {"functions": {"0x986720": "amJvspInit", ...},   <- 関数（関数エントリ）としてリネーム
//    "globals":   {"0x1696f38": "amDebug_logLevel"},  <- data symbol としてラベル付け（createLabel）
//    "notes":     {"0x55c7bc": "..."}}                <- ドキュメント用のみ。適用しない
// key = static_VA = Ghidra の番地そのもの、ImageBase 0x400000、小文字 hex。
// 関数エントリが存在する箇所は関数をリネームし、"functions"/"globals" セクションの残りのキーには
// primary data label を付ける。これで逆コンパイルが DAT_* ではなく amDebug_logLevel 等を表示する。
// "notes" 配下のキーは意図的にスキップする（関数中間オフセット / 識別子でない散文値）。
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ApplyKnownNames extends GhidraScript {
    @Override
    public void run() throws Exception {
        // data/known_names.json をこのスクリプトの位置を基準に解決する（リポジトリルートに依存しない）。
        // script dir = tools/ghidra_mcp/ghidra_scripts -> リポジトリルートは 3 階層上。
        java.io.File scriptsDir = getSourceFile().getParentFile().getFile(false);
        java.io.File repoRoot = scriptsDir.getParentFile().getParentFile().getParentFile();
        String path = new java.io.File(repoRoot, "data" + java.io.File.separator + "known_names.json").getPath();
        String json;
        try {
            json = new String(Files.readAllBytes(Paths.get(path)), "UTF-8");
        } catch (IOException e) {
            println("ApplyKnownNames: cannot read " + path + ": " + e.getMessage());
            return;
        }
        // "functions" と "globals" オブジェクトを切り出す。"notes" は意図的に除外する。
        String funcs   = section(json, "functions");
        String globals = section(json, "globals");

        int[] fn = apply(funcs,   true);   // functions: 関数エントリをリネーム、なければラベル付け
        int[] gl = apply(globals, false);  // globals: ラベル付けのみ（関数リネームなし）
        println("ApplyKnownNames: functions renamed=" + fn[0] + " labeled=" + fn[1] +
                " skipped=" + fn[2] + " | globals labeled=" + gl[1] + " skipped=" + gl[2]);
    }

    // 指定した top-level JSON オブジェクトの {...} 本体を返す。無ければ "" を返す。
    private String section(String json, String key) {
        int k = json.indexOf("\"" + key + "\"");
        if (k < 0) return "";
        int open = json.indexOf('{', k);
        if (open < 0) return "";
        int depth = 0;
        for (int i = open; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '{') depth++;
            else if (c == '}') { depth--; if (depth == 0) return json.substring(open, i + 1); }
        }
        return "";
    }

    // `body` 内の "0xVA": "name" ペアを適用する。renameFunc が真でその番地に関数エントリが
    // 存在すれば関数をリネームし、そうでなければ primary data label を作成/置換する。
    // {renamed, labeled, skipped} を返す。
    private int[] apply(String body, boolean renameFunc) {
        int renamed = 0, labeled = 0, skipped = 0;
        if (body.isEmpty()) return new int[]{0, 0, 0};
        Pattern p = Pattern.compile("\"(0x[0-9a-fA-F]+)\"\\s*:\\s*\"([^\"]+)\"");
        Matcher m = p.matcher(body);
        while (m.find()) {
            long va;
            try { va = Long.parseLong(m.group(1).substring(2), 16); }
            catch (NumberFormatException ex) { skipped++; continue; }
            String name = m.group(2);
            Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(va);
            try {
                Function f = renameFunc ? getFunctionAt(addr) : null;
                if (f != null) {
                    if (!f.getName().equals(name)) f.setName(name, SourceType.USER_DEFINED);
                    renamed++;
                } else {
                    // Data symbol: この番地で我々の名前を primary label にする。
                    createLabel(addr, name, true, SourceType.USER_DEFINED);
                    labeled++;
                }
            } catch (Exception ex) { skipped++; }
        }
        return new int[]{renamed, labeled, skipped};
    }
}
