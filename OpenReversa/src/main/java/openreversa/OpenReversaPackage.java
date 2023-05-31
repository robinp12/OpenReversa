package openreversa;

import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

public class OpenReversaPackage extends PluginPackage {
    public static final String NAME = "OpenReversa";
    public static final String HELP_NAME = "openfunctionid";
    public static final String SHORT_DESCRIPTION = "This plugin provides the access to the OpenReversa Database";
    public static final String OPENFIDB_ICON = "images/OpenFiDb_small.png";

    public OpenReversaPackage() {
        super(NAME, ResourceManager.loadImage(OPENFIDB_ICON),
                SHORT_DESCRIPTION);
    }

    public static void println(PluginTool tool, String s) {
        tool.getService(ConsoleService.class).println(s);
    }
}
