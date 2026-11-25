// re 的批量反编译脚本：把目标里所有函数反编译到一个文件。
// 用法：analyzeHeadless ... -postScript DumpAll.java <outfile>
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.io.PrintWriter;

public class DumpAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("RE_BAD_ARGS");
            return;
        }
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        FunctionManager manager = currentProgram.getFunctionManager();
        int total = 0, ok = 0;
        try (PrintWriter out = new PrintWriter(args[0], "UTF-8")) {
            for (Function function : manager.getFunctions(true)) {
                total++;
                out.println("// === " + function.getName() + " @ " + function.getEntryPoint()
                        + " size=" + function.getBody().getNumAddresses());
                DecompileResults results = decompiler.decompileFunction(function, 90, monitor);
                if (results != null && results.decompileCompleted()) {
                    out.println(results.getDecompiledFunction().getC());
                    ok++;
                } else {
                    out.println("/* decompile failed */");
                }
                out.println();
            }
        }
        println("RE_DONE " + ok + "/" + total);
    }
}
