// Applies data/known_names.json (static_VA -> friendly name) to the live Ghidra program at
// startup, so mcp__ghidra__* output shows our names. analyzeHeadless does not persist renames,
// so this runs every server start (as a -preScript, before GhidraMCPHeadless.java).
// known_names.json shape:
//   {"functions": {"0x986720": "amJvspInit", ...},   <- renamed as functions (function entry)
//    "globals":   {"0x1696f38": "amDebug_logLevel"},  <- labeled as data symbols (createLabel)
//    "notes":     {"0x55c7bc": "..."}}                <- documentation only, NOT applied
// key = static_VA = the Ghidra address directly, ImageBase 0x400000, lowercase hex.
// Functions are renamed where a function entry exists; remaining keys in the "functions"/"globals"
// sections get a primary data label so decompilation shows e.g. amDebug_logLevel instead of DAT_*.
// Keys under "notes" are skipped on purpose (mid-function offsets / non-identifier prose values).
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
        // Resolve data/known_names.json relative to this script's location (repo-root independent).
        // script dir = tools/ghidra_mcp/ghidra_scripts -> repo root is three levels up.
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
        // Slice out the "functions" and "globals" objects; "notes" is intentionally excluded.
        String funcs   = section(json, "functions");
        String globals = section(json, "globals");

        int[] fn = apply(funcs,   true);   // functions: rename function entry, else label
        int[] gl = apply(globals, false);  // globals: label only (no function rename)
        println("ApplyKnownNames: functions renamed=" + fn[0] + " labeled=" + fn[1] +
                " skipped=" + fn[2] + " | globals labeled=" + gl[1] + " skipped=" + gl[2]);
    }

    // Returns the {...} body of the named top-level JSON object, or "" if absent.
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

    // Applies "0xVA": "name" pairs in `body`. If renameFunc and a function entry exists at the
    // address, rename the function; otherwise create/replace a primary data label.
    // Returns {renamed, labeled, skipped}.
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
                    // Data symbol: make our name the primary label at this address.
                    createLabel(addr, name, true, SourceType.USER_DEFINED);
                    labeled++;
                }
            } catch (Exception ex) { skipped++; }
        }
        return new int[]{renamed, labeled, skipped};
    }
}
