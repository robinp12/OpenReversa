package openfunctionid;

import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

public class OpenFunctionIDPackage extends PluginPackage {
    public static final String NAME = "OpenFiDb";
    public static final String HELP_NAME = "openfunctionid";
    public static final String SHORT_DESCRIPTION = "This plugin provides the access to the OpenFunctionID Database";
    public static final String OPENFIDB_ICON = "images/OpenFiDb_small.png";

    public OpenFunctionIDPackage() {
        super(NAME, ResourceManager.loadImage(OPENFIDB_ICON),
                SHORT_DESCRIPTION);
    }

    public static void println(PluginTool tool, String s) {
        tool.getService(ConsoleService.class).println(s);
    }
}
