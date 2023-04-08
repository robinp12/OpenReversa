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
import ghidra.feature.fid.plugin.ActiveFidConfigureDialog;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.io.FileUtils;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Frame;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.JFileChooser;
import javax.swing.JComponent;
import javax.swing.filechooser.FileNameExtensionFilter;

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


public class OpenFunctionIDPlugin extends ProgramPlugin{

	private static final String FUNCTION_ID_NAME = "Function ID";
    private static final String MENU_GROUP_1 = "group1";
    private static final String MENU_GROUP_2 = "group2";
    private static final String REPO_URL = "https://github.com/Cyjanss/OpenFiDb.git";
    private static final String REPO_NAME = "OpenFiDb";
    

    private FidFileManager fidFileManager;

    private List<File> openFiDbFiles;
    private List<String> openFiDbFilesNames;

    private DockingAction loginAction;
    private DockingAction pullAction;
    private DockingAction pushAction;
    private DockingAction deleteAction;
    private DockingAction discardAction;

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
        pullAction.setEnabled(false);
        pushAction.setEnabled(false);
        deleteAction.setEnabled(false);
        discardAction.setEnabled(false);
    }

    @Override
    protected void cleanup() {
        super.cleanup();
    }

    private void createActions() {
        DockingAction action;

      // Login 
        action = new DockingAction("Login", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
            	LoginDialog login = new LoginDialog(loginAction,pullAction,pushAction,deleteAction,discardAction);
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "login"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Login"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        loginAction = action;
        
        //Pull the repo
        action = new DockingAction("Pull the repo", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {

                Msg.showInfo(getClass(), null, "Pull the repo",
                        "The OpenFiDb repository containing all FiDbs is about to be downloaded and all Fidbs files attached...");

                Task cloningTask = new Task("Cloning the OpenFiDb repository") {
                    @Override
                    public void run(TaskMonitor monitor) throws CancelledException {
                        if(Application.getMyModuleRootDirectory() != null){
                            if (Files.exists(Path.of(Application.getMyModuleRootDirectory().getAbsolutePath() + "/data/OpenFiDb"))){
                                println("Pulling the repo...");
                                pullRepo();
                            } else {
                                println("Cloning the repo...");
                                cloneRepo();
                            }
                        }
                        updateOpenFiDbFiles();
                        attachAll();
                        chooseActive();
                    }
                };
                TaskLauncher.launch(cloningTask);
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "pulltherepo"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Pull the repo"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        pullAction = action;
        
        //Push FiDb files
        action = new DockingAction("Push FiDb files",getName()) {
            @Override
            public void actionPerformed(ActionContext context) { 
            	pushOpenFiDbFiles();
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "push"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Push FiDb files"},
                null, MENU_GROUP_2, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        pushAction = action;

        //Delete all openFiDb files
        action = new DockingAction("Delete all openFiDb files",getName()) {
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

        //Discard local changes
        action = new DockingAction("Discard local changes",getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                discardLocalChanges();
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "discardlocal"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Discard local changes"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "2"));
        this.tool.addAction(action);
        discardAction = action;

    }

    private void pullRepo(){
        ProcessBuilder processBuilder = new ProcessBuilder()
                .command("git", "-C", REPO_NAME,"pull","--recurse-submodules")
                .directory(new File(Application.getMyModuleRootDirectory().getAbsolutePath()+"/data"));
        try {
            startProcess("GitPull",processBuilder);
        } catch (IOException e) {
            Msg.showError(getClass(),null,"Clone repository error",e);
        }

    }

    private void cloneRepo(){
        File dir = new File(Application.getMyModuleRootDirectory().getAbsolutePath()+"/data");
        ProcessBuilder processBuilder = new ProcessBuilder()
                .command("git", "clone", "--recurse-submodules", REPO_URL)
                .directory(dir);
        ProcessBuilder initSubmodule = new ProcessBuilder()
                .command("git","submodule","update","--init","--recursive")
                .directory(dir);
        try {
            startProcess("GitClone",processBuilder);
            //startProcess("GitInitSubmodules",initSubmodule);
        } catch (IOException e) {
            Msg.showError(getClass(),null,"Pull repository error",e);
        }
    }

    private void discardLocalChanges(){
        ProcessBuilder processBuilder = new ProcessBuilder()
                .command("git", "-C", REPO_NAME,"restore",".")
                .directory(new File(Application.getMyModuleRootDirectory().getAbsolutePath()+"/data"));
        try {
            startProcess("GitDiscardLocalChanges",processBuilder);
            Msg.showInfo(getClass(),null,"Local changes discarded","All local changes have been discarded");
        } catch (IOException e) {
            Msg.showError(getClass(),null,"Discard local changes error",e);
        }
    }

    private void statusRepo(){
        ProcessBuilder processBuilder = new ProcessBuilder()
                .command("git", "-C", REPO_NAME,"status")
                .directory(new File(Application.getMyModuleRootDirectory().getAbsolutePath()+"/data"));
        try {
            Process p = processBuilder.start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(p.getErrorStream()));

            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append(line).append("\n");
            }
            Msg.showInfo(getClass(),null,"Repository status",output.toString());
            println(findModified(output.toString()).toString());

        } catch (IOException e) {
            Msg.showError(getClass(),null,"Status repository error",e);
        }
    }

    private List<String> findModified(String searchString){
        List<String> modifiedFiles = null;
        for (String line: searchString.split("\n")){
            if (line.contains("modified:") && line.contains("Collaborative")){
                String file = line.split("Collaborative")[1].trim();
                modifiedFiles.add(file);
            }
        }
        return modifiedFiles;
    }

    private void attachAll(){
        List<FidFile> originalFidFiles = fidFileManager.getFidFiles();
        List<String> originalFidFilesNames = new ArrayList<>();
        originalFidFiles.forEach(originalFidFile -> originalFidFilesNames.add(originalFidFile.getName()));

        for (File file: openFiDbFiles) {
            if (file != null && !originalFidFilesNames.contains(file.getName())){
                fidFileManager.addUserFidFile(file);
                println("FiDb file : "+file.getName()+" attached.");
            }
        }

        //Set inactive, only for new fidbfiles
        List<FidFile> fidFiles = fidFileManager.getFidFiles();

        for (FidFile fidFile: fidFiles) {
            String fidFileName = fidFile.getName();
            if (openFiDbFilesNames.contains(fidFileName) && !originalFidFilesNames.contains(fidFileName)){
                fidFile.setActive(false);
            }
        }
    }

    private synchronized void chooseActive(){
        ActiveFidConfigureDialog dialog =
                new ActiveFidConfigureDialog(fidFileManager.getFidFiles());
        tool.showDialog(dialog);
    }

    private void removeAndDeleteAll(){
        List<FidFile> fidFiles = fidFileManager.getFidFiles();
        for (File openFiDbFile: openFiDbFiles){
            for (FidFile fidFile: fidFiles){
                if (openFiDbFile.getName().equals(fidFile.getName())){
                    fidFileManager.removeUserFile(fidFile);
                    openFiDbFile.delete();
                }
            }
        }
        File gitDir = new File(Application.getMyModuleRootDirectory().getAbsolutePath()+"/data/"+REPO_NAME);
        try {
            FileUtils.deleteDirectory(gitDir);
        } catch (IOException e) {
            Msg.showError(getClass(),null,"Couldn't delete the directory",e);
        }
        println("OpenFiDb folder deleted.");
        updateOpenFiDbFiles();
    }
    
    /*private static boolean pushRequest(List<FidFile> fidFile, File openFiDbFile) {
    	
    	return false;
    }*/
    
    private void pushOpenFiDbFiles() {
    	JFileChooser chooser = new JFileChooser();
        FileNameExtensionFilter filter = new FileNameExtensionFilter(
            "fidb files", "fidb");
        chooser.setFileFilter(filter);
        int returnVal = chooser.showOpenDialog(null);
        if(returnVal == JFileChooser.APPROVE_OPTION) {
           System.out.println("You chose to open this file: " +
                chooser.getSelectedFile().getName());
        }
    }

    private void updateOpenFiDbFiles(){
        List<ResourceFile> resourceFiles = Application.findFilesByExtensionInMyModule(".fidb");
        openFiDbFiles = new ArrayList<>();
        resourceFiles.forEach(resourceFile -> openFiDbFiles.add(resourceFile.getFile(false)));
        openFiDbFilesNames = new ArrayList<>();
        openFiDbFiles.forEach(dbFile -> openFiDbFilesNames.add(dbFile.getName()));
    }

    private void enableActions() {
    	loginAction.setEnabled(false);
        pullAction.setEnabled(true);
        pushAction.setEnabled(true);
        deleteAction.setEnabled(true);
        discardAction.setEnabled(true);
    }

    private void startProcess(String name, ProcessBuilder processBuilder) throws IOException {
        Process p = processBuilder.start();
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(p.getInputStream()));
        BufferedReader stdError = new BufferedReader(new InputStreamReader(p.getErrorStream()));

        String s = null;
        while ((s = stdInput.readLine()) != null) {
            println(name+" |"+s);
        }

        while ((s = stdError.readLine()) != null) {
            println(name+" |"+s);
        }
    }
    private void println(String s){
        OpenFunctionIDPackage.println(tool,"[OpenFunctionID] "+s);
    }
}