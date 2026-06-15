#!/usr/bin/env python3
"""Generate a headless GhidraScript port of GhidraMCPPlugin.java.
Converts the GUI Plugin into a GhidraScript that starts the same HTTP server
using `currentProgram` (no PluginTool / Swing GUI required), so it can run under
analyzeHeadless and serve the MCP bridge with zero Ghidra GUI."""
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

# 1. drop package (Ghidra scripts live in the default package)
sub("package com.lauriewired;\n", "")

# 2. swap the Plugin import for the GhidraScript import
sub("import ghidra.framework.plugintool.Plugin;\n",
    "import ghidra.app.script.GhidraScript;\n")

# 3. remove @PluginInfo and make the class a GhidraScript
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

# 4. constructor -> run() that starts the server and blocks
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

# 5. fixed port instead of tool options
sub(
'''        // Read the configured port
        Options options = tool.getOptions(OPTION_CATEGORY_NAME);
        int port = options.getInt(PORT_OPTION_NAME, DEFAULT_PORT);''',
"        int port = DEFAULT_PORT;")

# 6. getCurrentAddress -> program min address (no CodeViewerService)
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

# 7. getCurrentFunction -> first function (no CodeViewerService)
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

# 8. drop the tool-based getCurrentProgram override; inherit GhidraScript's
sub(
'''    public Program getCurrentProgram() {
        ProgramManager pm = tool.getService(ProgramManager.class);
        return pm != null ? pm.getCurrentProgram() : null;
    }

''',
"")

# 9. DataTypeManagerService is GUI-only; null is fine for headless parsing
sub("tool.getService(ghidra.app.services.DataTypeManagerService.class)", "null")

# 10. remove the Plugin.dispose() override (server stop handled by shutdown hook)
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
