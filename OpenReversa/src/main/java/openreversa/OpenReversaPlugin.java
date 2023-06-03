/**
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
package openreversa;

import java.util.ArrayList;
import java.util.List;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * This is the main plugin class for the OpenReversa plugin.
 * It extends the ProgramPlugin class provided by the GHIDRA framework.
 */
//@formatter:off
@PluginInfo(
        status = PluginStatus.STABLE,
        packageName = OpenReversaPackage.NAME,
        category = PluginCategoryNames.SEARCH,
        shortDescription = OpenReversaPackage.SHORT_DESCRIPTION,
        description = OpenReversaPackage.SHORT_DESCRIPTION
)
//@formatter:on
public class OpenReversaPlugin extends ProgramPlugin {

    // Constants for menu groups and action names
    private static final String FUNCTION_ID_NAME = "Function ID";
    private static final String MENU_GROUP_0 = "group0";
    private static final String MENU_GROUP_1 = "group1";
    private static final String MENU_GROUP_2 = "group2";

    // Instance variables
    private DockingAction loginAction;
    private DockingAction pullAction;
    private DockingAction logoutAction;
    private DockingAction populateAction;
    private DockingAction removeAction;
    private Request request = new Request();

    /**
     * Plugin constructor.
     *
     * @param tool The plugin tool that this plugin is added to.
     */
    public OpenReversaPlugin(PluginTool plugintool) {
        super(plugintool);
    }

    /**
     * Initializes the plugin by setting up actions and enabling only the login if user not connected.
     */
    @Override
    public void init() {
        super.init();
        createActions();
        loginAction.setEnabled(true);
        logoutAction.setEnabled(false);
        populateAction.setEnabled(false);
        pullAction.setEnabled(false);
        removeAction.setEnabled(false);
    }

    /**
     * Performs cleanup operations when the plugin is unloaded or the application is closed.
     */
    @Override
    protected void cleanup() {
        super.cleanup();
    }

    /**
     * Creates the actions for the plugin and associates them with menu items.
     */
    private void createActions() {
        DockingAction action;

        // Login Action
        action = new DockingAction("Login", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                new LoginDialog(loginAction, pullAction, logoutAction, removeAction, populateAction);
            }
        };
        action.setHelpLocation(new HelpLocation(OpenReversaPackage.HELP_NAME, "login"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenReversaPackage.NAME, "Login"},
                null, MENU_GROUP_0, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        loginAction = action;

        // Delete function Action
        action = new DockingAction("Delete Function", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    Request request = new Request();
                    request.removeRequest(LoginDialog.getUserId());
                } catch (Exception e) {
                    Msg.showError(getClass(), null, "Server Error", "Sorry, the server is currently unavailable. Please try again later.");
                    e.printStackTrace();
                }
            }
        };
        action.setHelpLocation(new HelpLocation(OpenReversaPackage.HELP_NAME, "delete function"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenReversaPackage.NAME, "Delete Function from Database"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "3"));
        this.tool.addAction(action);
        removeAction = action;

        // Logout Action
        action = new DockingAction("Logout", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                disableActions();
            }
        };
        action.setHelpLocation(new HelpLocation(OpenReversaPackage.HELP_NAME, "logout"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenReversaPackage.NAME, "Logout"},
                null, MENU_GROUP_2, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        logoutAction = action;

        // Adding function to DB Action
        action = new DockingAction("Add Function to Database", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                CustomPopulate c = new CustomPopulate();
                try {
                    c.libraryInput();
                } catch (Exception e) {
                    Msg.showError(getClass(), null, "Server Error", "Sorry, the server is currently unavailable. Please try again later.");
                    e.printStackTrace();
                }
            }
        };
        action.setHelpLocation(new HelpLocation(OpenReversaPackage.HELP_NAME, "Add function to database"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenReversaPackage.NAME, "Share Function in Database"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        populateAction = action;

        // Retrieve function from database Action
        action = new DockingAction("Pull Function from Database", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                try {
                    pullDialog();
                } catch (Exception e) {
                    Msg.showError(getClass(), null, "Server Error", "Sorry, the server is currently unavailable. Please try again later.");
                    e.printStackTrace();
                }
            }
        };
        action.setHelpLocation(new HelpLocation(OpenReversaPackage.HELP_NAME, "pull function from database"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenReversaPackage.NAME, "Pull Database's Function(s) in Fidb"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "2"));
        this.tool.addAction(action);
        pullAction = action;
    }

    /**
     * Show the functions from the database in order to be able to choose which ones to pull.
     */
    public boolean pullDialog() throws Exception {
        List<List<String>> result = request.pullRequest();
        ArrayList<FunctionItem> output = new ArrayList<FunctionItem>();

        for (List<String> list : result) {
            String[] field = list.get(0).split(",");
            String user = field[0].replaceAll("\"", "").trim();
            String codeUnitSize = field[1].replaceAll("\"", "").trim();
            String fullHash = field[2].replaceAll("\"", "").trim();
            String specificHashAdditionalSize = field[3].replaceAll("\"", "").trim();
            String specificHash = field[4].replaceAll("\"", "").trim();
            String library_name = field[5].replaceAll("\"", "").trim();
            String library_version = field[6].replaceAll("\"", "").trim();
            String library_variant = field[7].replaceAll("\"", "").trim();
            String Ghidraversion = field[8].replaceAll("\"", "").trim();
            String Languageversion = field[9].replaceAll("\"", "").trim();
            String Languageminorversion = field[10].replaceAll("\"", "").trim();
            String Compilerspecid = field[11].replaceAll("\"", "").trim();
            String Entrypoint = field[12].replaceAll("\"", "").trim();
            String Languageid = field[13].replaceAll("\"", "").trim();
            String funName = field[14].replaceAll("\"", "").trim();
            String signature = field[15].replaceAll("\"", "").trim();
            String Codec = field[16].replaceAll("\"", "").trim();
            String comment = field[17].replaceAll("\"", "").trim();

            FunctionItem item = new FunctionItem(user, Short.parseShort(codeUnitSize), Long.parseLong(fullHash),
                    Byte.parseByte(specificHashAdditionalSize), Long.parseLong(specificHash),
                    library_name, library_version, library_variant, Ghidraversion, new LanguageID(Languageid),
                    Integer.parseInt(Languageversion), Integer.parseInt(Languageminorversion),
                    new CompilerSpecID(Compilerspecid), funName, Long.parseLong(Entrypoint), signature, Codec, comment);
            output.add(item);
        }
        SelectionDialog dialog = new SelectionDialog(output, false);
        tool.showDialog(dialog);
        return true;
    }
    
    /**
     * disable all actions except login 
     */
    private void disableActions() {
        loginAction.setEnabled(true);
        logoutAction.setEnabled(false);
        populateAction.setEnabled(false);
        pullAction.setEnabled(false);
        removeAction.setEnabled(false);
    }
}