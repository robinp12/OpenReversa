package openfunctionid;

import docking.DialogComponentProvider;
import docking.action.ToolBarData;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.actions.ExportToCAction;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import resources.ResourceManager;

import java.io.*;

public class OpenFunctionIDUploadC extends ExportToCAction {

    String codeC;
    String name;

    OpenFunctionIDUploadC() {
        super();
        super.setToolBarData(new ToolBarData(ResourceManager.loadImage(OpenFunctionIDPackage.OPENFIDB_ICON), "Local"));
        super.setDescription("Save pseudocode to C file");
        super.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "save"));
    }

    @Override
    protected void decompilerActionPerformed(DecompilerActionContext context) {
        getCCode(context);
        new SendToOpenFiDbDialog(context, codeC, name);
    }

    private boolean getCCode(DecompilerActionContext context) {
        ClangTokenGroup grp = context.getCCodeModel();
        PrettyPrinter printer = new PrettyPrinter(context.getFunction(), grp);
        name = printer.getFunction().getName();
        DecompiledFunction decompFunc = printer.print(true);
        codeC = decompFunc.getC();
        return verifyCCode(context);
    }

    protected boolean verifyCCode(DecompilerActionContext context) {
        if (codeC.trim().isEmpty()) {
            Msg.showError(getClass(), context.getDecompilerPanel(), "\n No code C to extract and send",
                    "There is no decompiled code in the Decompiler Panel to send to OpenFiDb,\n" +
                            "\nPlease verify and retry");
            return false;
        } else {
            return true;
        }
    }

}

class SendToOpenFiDbDialog extends DialogComponentProvider {

    DecompilerActionContext context;
    String codeC;
    private String name;

    protected SendToOpenFiDbDialog(DecompilerActionContext context, String codeC, String name) {
        super("Save pseudocode in local");
        this.context = context;
        this.codeC = codeC;
        this.name = name;

        writeCfile("PseudoCode_" + name + ".c");
        setRememberSize(false);
        setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "save"));

    }

    private void writeCfile(String fileName) {

        try {
            FileWriter fileWriter = new FileWriter(fileName);
            fileWriter.write(codeC);

            fileWriter.close();
            Msg.showInfo(getClass(), null, "Success", "File '" + name + "' successfully written.");

            System.out.println("File written successfully.");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            Msg.showError(getClass(), null, "An error occurred", "File not saved.");

            e.printStackTrace();
        }
    }

}