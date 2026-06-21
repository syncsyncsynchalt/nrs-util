#!/usr/bin/env python3
"""GhidraMCPPlugin.java を headless 版 GhidraScript に変換して生成する。
GUI 用 Plugin を、同じ HTTP サーバを `currentProgram` で起動する GhidraScript に
変換する（PluginTool / Swing GUI 不要）。これにより analyzeHeadless 上で動かし、
Ghidra GUI なしで MCP bridge を提供できる。"""
import os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))   # tools/ghidra_mcp
SRC = os.path.join(_HERE, "src", "src", "main", "java", "com", "lauriewired", "GhidraMCPPlugin.java")
OUT = os.path.join(_HERE, "ghidra_scripts", "GhidraMCPHeadless.java")

s = open(SRC, encoding="utf-8").read()

def sub(old, new, n=1):
    global s
    c = s.count(old)
    assert c == n, f"expected {n} match, got {c} for:\n{old[:120]!r}"
    s = s.replace(old, new)

# 1. package 宣言を削除（Ghidra スクリプトは default package に置く）
sub("package com.lauriewired;\n", "")

# 2. Plugin import を GhidraScript import に差し替え
sub("import ghidra.framework.plugintool.Plugin;\n",
    "import ghidra.app.script.GhidraScript;\n")

# 3. @PluginInfo を除去し、クラスを GhidraScript にする
sub(
'''@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "HTTP server plugin",
    description = "Starts an embedded HTTP server to expose program data. Port configurable via Tool Options."
)
public class GhidraMCPPlugin extends Plugin {''',
"public class GhidraMCPHeadless extends GhidraScript {")

# 4. コンストラクタ -> サーバを起動してブロックする run() に置換
sub(
'''    public GhidraMCPPlugin(PluginTool tool) {
        super(tool);
        Msg.info(this, "GhidraMCPPlugin loading...");

        // Register the configuration option
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        options.registerOption(PORT_OPTION_NAME, DEFAULT_PORT,
            null, // No help location for now
            "The network port number the embedded HTTP server will listen on. " +
            "Requires Ghidra restart or plugin reload to take effect after changing.");

        try {
            startServer();
        }
        catch (IOException e) {
            Msg.error(this, "Failed to start HTTP server", e);
        }
        Msg.info(this, "GhidraMCPPlugin loaded!");
    }''',
'''    @Override
    public void run() throws Exception {
        Msg.info(this, "GhidraMCPHeadless starting...");
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            if (server != null) { server.stop(0); }
        }));
        startServer();
        Msg.info(this, "GhidraMCP HTTP server listening on port " + DEFAULT_PORT + " (headless).");
        while (true) { Thread.sleep(3600000L); }
    }''')

# 5. tool options ではなく固定ポートを使う
sub(
'''        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);''',
"        int port = DEFAULT_PORT;")

# 6. getCurrentAddress -> program の最小アドレス（CodeViewerService 不使用）
sub(
'''    private String getCurrentAddress() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        return (location != null) ? location.getAddress().toString() : "No current location";
    }''',
'''    private String getCurrentAddress() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        return program.getMinAddress().toString();
    }''')

# 7. getCurrentFunction -> 先頭の関数（CodeViewerService 不使用）
sub(
'''    private String getCurrentFunction() {
        CodeViewerService service = tool.getService(CodeViewerService.class);
        if (service == null) return "Code viewer service not available";

        ProgramLocation location = service.getCurrentLocation();
        if (location == null) return "No current location";

        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";

        Function func = program.getFunctionManager().getFunctionContaining(location.getAddress());
        if (func == null) return "No function at current location: " + location.getAddress();

        return String.format("Function: %s at %s\\nSignature: %s",
            func.getName(),
            func.getEntryPoint(),
            func.getSignature());
    }''',
'''    private String getCurrentFunction() {
        Program program = getCurrentProgram();
        if (program == null) return "No program loaded";
        java.util.Iterator<Function> it = program.getFunctionManager().getFunctions(true).iterator();
        if (!it.hasNext()) return "No functions";
        Function func = it.next();
        return String.format("Function: %s at %s\\nSignature: %s",
            func.getName(), func.getEntryPoint(), func.getSignature());
    }''')

# 8. tool ベースの getCurrentProgram override を削除し、GhidraScript のものを継承
sub(
'''    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

''',
"")

# 9. DataTypeManagerService は GUI 専用。headless での parse では null で問題ない
sub("tool.getService(ghidra.app.services.DataTypeManagerService.class)", "null")

# 10. Plugin.dispose() override を削除（サーバ停止は shutdown hook で処理）
sub(
'''    @Override
    public void dispose() {
        if (server != null) {
            Msg.info(this, "Stopping GhidraMCP HTTP server...");
            server.stop(1); // Stop with a small delay (e.g., 1 second) for connections to finish
            server = null; // Nullify the reference
            Msg.info(this, "GhidraMCP HTTP server stopped.");
        }
        super.dispose();
    }
''',
"")

for bad in ("tool.getService", "tool.getOptions", "super(tool)", "(PluginTool tool)"):
    assert bad not in s, f"leftover GUI reference: {bad}"
assert "GhidraMCPPlugin" not in s, "leftover GhidraMCPPlugin reference"

os.makedirs(os.path.dirname(OUT), exist_ok=True)
open(OUT, "w", encoding="utf-8", newline="\n").write(s)
print(f"OK: wrote {OUT} ({len(s.splitlines())} lines); no tool./GhidraMCPPlugin refs remain")
