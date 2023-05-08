/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package openfunctionid;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import generic.jar.ResourceFile;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.db.FidFileManager;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.feature.fid.plugin.ActiveFidConfigureDialog;


/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = OpenFunctionIDPackage.NAME,
        category = PluginCategoryNames.SEARCH,
        shortDescription = OpenFunctionIDPackage.SHORT_DESCRIPTION,
        description = OpenFunctionIDPackage.SHORT_DESCRIPTION
)
//@formatter:on


public class OpenFunctionIDPlugin extends ProgramPlugin {

    private static final String FUNCTION_ID_NAME = "Function ID";
    private static final String MENU_GROUP_0 = "group0";
    private static final String MENU_GROUP_1 = "group1";
    private static final String MENU_GROUP_2 = "group2";
    //private static final String REPO_URL = "https://github.com/Cyjanss/OpenFiDb.git";
    private static final String REPO_NAME = "OpenFiDb";


    private FidFileManager fidFileManager;
    private File file;

    Request request = new Request();

    private List<File> openFiDbFiles;
    private List<String> openFiDbFilesNames;

    private DockingAction loginAction;
    private DockingAction pullAction;
    private DockingAction deleteAction;
    private DockingAction logoutAction;
    private DockingAction populateAction;
    private DockingAction removeAction;

    /**
     * Plugin constructor.
     *
     * @param tool The plugin tool that this plugin is added to.
     */
    public OpenFunctionIDPlugin(PluginTool plugintool) {
        super(plugintool);
        // TODO Auto-generated constructor stub
    }

    @Override
    public void init() {
        super.init();
        fidFileManager = FidFileManager.getInstance();
        OpenFunctionIDUploadC uploadCAction = new OpenFunctionIDUploadC();
        tool.getComponentProvider("Decompiler").addLocalAction(uploadCAction);
        updateOpenFiDbFiles();
        createActions();
        loginAction.setEnabled(true);
        logoutAction.setEnabled(false);
        populateAction.setEnabled(false);
        pullAction.setEnabled(false);
        deleteAction.setEnabled(false);
        removeAction.setEnabled(false);
    }

    @Override
    protected void cleanup() {
        super.cleanup();
    }

    private void createActions() {
        DockingAction action;

        //Login 
        action = new DockingAction("Login", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                LoginDialog login = new LoginDialog(loginAction, pullAction, deleteAction, logoutAction, removeAction, populateAction);
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "login"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Login"},
                null, MENU_GROUP_0, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        loginAction = action;

        //remove
        action = new DockingAction("delete function", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    Request request = new Request();
                    request.removeRequest(LoginDialog.getUserId());
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "delete function"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Delete function from database"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "3"));
        this.tool.addAction(action);
        removeAction = action;

        //Logout
        action = new DockingAction("Logout", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                disableActions();
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "logout"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Logout"},
                null, MENU_GROUP_2, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        logoutAction = action;

        //DB Populate
        action = new DockingAction("Add function to database", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {

                CustomPopulate c = new CustomPopulate();

                try {
                    c.libraryInput();
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }

        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "Add function to database"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Share function in database"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        populateAction = action;

        //Pull the repo
        action = new DockingAction("Pull function from database", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    pullDialog();
                } catch (Exception e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "pull function from database"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Pull database's function(s) in fidb"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "2"));
        this.tool.addAction(action);
        pullAction = action;

        //Delete all openFiDb files
        action = new DockingAction("Delete all openFiDb files", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                removeAndDeleteAll();
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "delete"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Delete all OpenFiDb files"},
                null, MENU_GROUP_2, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        deleteAction = action;

    }

    private void attachAll() {
        List<FidFile> originalFidFiles = fidFileManager.getFidFiles();
        List<String> originalFidFilesNames = new ArrayList<>();
        originalFidFiles.forEach(originalFidFile -> originalFidFilesNames.add(originalFidFile.getName()));

        for (File file : openFiDbFiles) {
            if (file != null && !originalFidFilesNames.contains(file.getName())) {
                fidFileManager.addUserFidFile(file);
                println("FiDb file : " + file.getName() + " attached.");
            }
        }

        //Set inactive, only for new fidbfiles
        List<FidFile> fidFiles = fidFileManager.getFidFiles();

        for (FidFile fidFile : fidFiles) {
            String fidFileName = fidFile.getName();
            if (openFiDbFilesNames.contains(fidFileName) && !originalFidFilesNames.contains(fidFileName)) {
                fidFile.setActive(false);
            }
        }
    }

    private synchronized void chooseActive() {
        ActiveFidConfigureDialog dialog =
                new ActiveFidConfigureDialog(fidFileManager.getFidFiles());
        tool.showDialog(dialog);
    }

    private void removeAndDeleteAll() {
        List<FidFile> fidFiles = fidFileManager.getFidFiles();
        for (File openFiDbFile : openFiDbFiles) {
            for (FidFile fidFile : fidFiles) {
                if (openFiDbFile.getName().equals(fidFile.getName())) {
                    fidFileManager.removeUserFile(fidFile);
                    openFiDbFile.delete();
                }
            }
        }
        File gitDir = new File(Application.getMyModuleRootDirectory().getAbsolutePath() + "/data/" + REPO_NAME);
        try {
            FileUtils.deleteDirectory(gitDir);
        } catch (IOException e) {
            Msg.showError(getClass(), null, "Couldn't delete the directory", e);
        }
        println("OpenFiDb folder deleted.");
        updateOpenFiDbFiles();
    }

    private void show(Selection dialog) {
        tool.showDialog(dialog);
    }

    public boolean pullDialog() throws Exception {
        List<List<String>> result = request.pullRequest();

        ArrayList<MyItem> output = new ArrayList<MyItem>();

        for (List<String> list : result) {
            String[] field = list.get(0).split(",");
            String user = field[0].replaceAll("\"", "");

            String codeUnitSize = field[1].replaceAll("\"", "");
            String fullHash = field[2].replaceAll("\"", "");
            String specificHashAdditionalSize = field[3].replaceAll("\"", "");
            String specificHash = field[4].replaceAll("\"", "");


            String library_name = field[5].replaceAll("\"", "");
            String library_version = field[6].replaceAll("\"", "");
            String library_variant = field[7].replaceAll("\"", "");

            String Ghidraversion = field[8].replaceAll("\"", "");


            String Languageversion = field[9].replaceAll("\"", "");
            String Languageminorversion = field[10].replaceAll("\"", "");
            String Compilerspecid = field[11].replaceAll("\"", "");
            String Entrypoint = field[12].replaceAll("\"", "");
            String Languageid = field[13].replaceAll("\"", "");
            String funName = field[14].replaceAll("\"", "");
            String Codec = field[15].replaceAll("\"", "");

            MyItem item = new MyItem(user, Short.parseShort(codeUnitSize.trim()), Long.parseLong(fullHash.trim()),
                    Byte.parseByte(specificHashAdditionalSize.trim()), Long.parseLong(specificHash.trim()),
                    library_name, library_version,
                    library_variant, Ghidraversion, new LanguageID(Languageid),
                    Integer.parseInt(Languageversion.trim()), Integer.parseInt(Languageminorversion.trim()),
                    new CompilerSpecID(Compilerspecid), funName, Long.parseLong(Entrypoint.trim()), Codec);
            output.add(item);

        }
        Selection dialog = new Selection(output, false);
        tool.showDialog(dialog);
        return true;
    }


    private void updateOpenFiDbFiles() {
        List<ResourceFile> resourceFiles = Application.findFilesByExtensionInMyModule(".fidb");

        openFiDbFiles = new ArrayList<>();
        resourceFiles.forEach((resourceFile) -> {
            openFiDbFiles.add(resourceFile.getFile(false));
        });

        openFiDbFilesNames = new ArrayList<>();
        openFiDbFiles.forEach(dbFile -> openFiDbFilesNames.add(dbFile.getName()));
    }

    private void disableActions() {
        loginAction.setEnabled(true);
        logoutAction.setEnabled(false);
        populateAction.setEnabled(false);
        pullAction.setEnabled(false);
        deleteAction.setEnabled(false);
        removeAction.setEnabled(false);
    }

    private void enableActions() {
        loginAction.setEnabled(false);
        logoutAction.setEnabled(true);
        populateAction.setEnabled(true);
        pullAction.setEnabled(true);
        deleteAction.setEnabled(true);
        removeAction.setEnabled(true);
    }

    private void println(String s) {
        OpenFunctionIDPackage.println(tool, "[OpenFunctionID] " + s);
    }
}

