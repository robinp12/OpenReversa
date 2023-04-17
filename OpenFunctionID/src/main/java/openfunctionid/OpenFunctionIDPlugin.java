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
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListCellRenderer;
import javax.swing.ListSelectionModel;
import javax.swing.JFileChooser;
import javax.swing.JComponent;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipFile;
import java.io.BufferedOutputStream;
import javax.swing.JList;
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
    private File file;

    private List<File> openFiDbFiles;
    private List<String> openFiDbFilesNames;
    
    private static final String POST_URL = "http://127.0.0.1:5000/";

    private DockingAction loginAction;
    private DockingAction pullAction;
    private DockingAction pushAction;
    private DockingAction deleteAction;
    private DockingAction discardAction;
    private DockingAction logoutAction;

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

        //Login 
        action = new DockingAction("Login", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
            	LoginDialog login = new LoginDialog(loginAction,pullAction,pushAction,deleteAction,discardAction,logoutAction);
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "login"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Login"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        loginAction = action;
        
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
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        pushAction = action;
        
        //Pull the repo
        action = new DockingAction("Pull the repo",getName()) {
            @Override
            public void actionPerformed(ActionContext context) { 
            	try {
					Pullrequest();
					updateOpenFiDbFiles();
			        attachAll();
			        chooseActive();
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "pulltherepo"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Pull the repo"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        pullAction = action;
        
        //Pull the repo
        /*action = new DockingAction("Pull the repo", getName()) {
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
        pullAction = action;*/
        

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
    
    private static void sendPOST(File file) throws IOException {
        String fileName = file.getName();
        URL obj = new URL(POST_URL + "file");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/octet-stream");
        con.setRequestProperty("Content-Length", String.valueOf(file.length()));
        con.setRequestProperty("X-File-Name", fileName); // add this line to include the file name
        con.setRequestProperty("Username", LoginDialog.getUserId()); // add this line to include the file name
        con.setDoOutput(true);

        int chunkSize = 4096;
        byte[] buffer = new byte[chunkSize];
        try (FileInputStream fis = new FileInputStream(file);
             OutputStream os = con.getOutputStream()) {

            int bytesRead;
            while ((bytesRead = fis.read(buffer)) > 0) {
                os.write(buffer, 0, bytesRead);
                os.flush();
            }
        }

        int responseCode = con.getResponseCode();
        System.out.println("POST Response Code :: " + responseCode);

        if (responseCode == HttpURLConnection.HTTP_OK) { //success
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            // print result
            System.out.println(response.toString());
        } else if (responseCode == HttpURLConnection.HTTP_CONFLICT) { // file already exists in the database
        	String message = "This file has already been inserted into the database by ";
            message += con.getHeaderField("user_name") + ".";
            JOptionPane.showMessageDialog(null, message, "File Already Exists", JOptionPane.WARNING_MESSAGE);
        }  else {
            System.out.println("POST request did not work.");
        }
    }
    
    private void pushOpenFiDbFiles() {
    	JFileChooser chooser = new JFileChooser();
        FileNameExtensionFilter filter = new FileNameExtensionFilter(
            "fidb files", "fidb");
        chooser.setFileFilter(filter);
        int returnVal = chooser.showOpenDialog(null);
        if(returnVal == JFileChooser.APPROVE_OPTION) {
           System.out.println("You chose to open this file: " +
                chooser.getSelectedFile().getName());
           file = chooser.getSelectedFile();
           try {
			 sendPOST(file);
           } catch (IOException e) {
			// TODO Auto-generated catch block
			 e.printStackTrace();
           }
        }

    }
    
    public void Pullrequest() throws Exception {
    	
        URL url = new URL(POST_URL + "download_files");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            String contentType = connection.getContentType();
            String disposition = connection.getHeaderField("Content-Disposition");
            int contentLength = connection.getContentLength();

            List<String> fileNames = new ArrayList<>();

            if (disposition != null) {
                // extract the file names from the Content-Disposition header
                String[] parts = disposition.split("filename=");
                if (parts.length > 1) {
                    String fileName = parts[1].replaceAll("\"", "");
                    fileNames.add(fileName);
                }
            } else {
                // extract the file names from the URL
                String fileName = url.getFile();
                fileNames.add(fileName.substring(fileName.lastIndexOf("/") + 1));
            }

            // create the directory to store the files
            File dir = new File(Application.getMyModuleRootDirectory().getAbsolutePath()+"/data");
            if (!dir.exists()) {
                dir.mkdirs();
            }

            // download the files and save them to the directory
            InputStream inputStream = connection.getInputStream();
            byte[] buffer = new byte[4096];
            int bytesRead = -1;
            for (String fileName : fileNames) {
                String filePath = dir.getPath() + "/" + fileName;
                OutputStream outputStream = new FileOutputStream(filePath);
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                outputStream.close();
            }
            inputStream.close();

            String destDirectory = Application.getMyModuleRootDirectory().getAbsolutePath() + "/data/OpenFiDb";

            File destDir = new File(destDirectory);
            if (!destDir.exists()) {
                destDir.mkdirs();
            } else {
                File[] files = destDir.listFiles();
                for (File file : files) {
                    file.delete();
                }
            }
            selectAndExtractFilesFromZip(dir, fileNames, destDirectory);
        } else {
            System.out.println("Server returned response code " + responseCode);
        }
    }
  
    public void selectAndExtractFilesFromZip(File dir, List<String> fileNames, String destDirectory) throws IOException {
        List<String> fileNamesList = new ArrayList<>();
        try (ZipFile zipFile = new ZipFile(dir.getPath() + "/" + fileNames.get(0))) {
            Enumeration<? extends ZipEntry> entries = zipFile.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                fileNamesList.add(entry.getName());
            }
        }

        String[] options = fileNamesList.toArray(new String[fileNamesList.size()]);

        // Create a custom cell renderer to display checkboxes next to the list items
        ListCellRenderer<? super String> renderer = new JCheckBoxListCellRenderer();

        JList<String> list = new JList<>(options);
        list.setCellRenderer(renderer);
        list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);

        // Create a "Select All" button and add it to a panel above the list
        JButton selectAllButton = new JButton("Select All");
        selectAllButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Select all items in the list
                list.setSelectionInterval(0, options.length - 1);
            }
        });

        JPanel panel = new JPanel();
        panel.add(selectAllButton);

        JScrollPane scrollPane = new JScrollPane(list);
        scrollPane.setColumnHeaderView(panel);

        int option = JOptionPane.showConfirmDialog(null, scrollPane, "Select Files", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            List<String> selectedFileNames = list.getSelectedValuesList();
            if (selectedFileNames.isEmpty()) {
                // User did not select any files
                return;
            }

            for (String selectedFileName : selectedFileNames) {
                try (ZipInputStream zipStream = new ZipInputStream(new FileInputStream(dir.getPath() + "/" + fileNames.get(0)))) {
                    ZipEntry entry = zipStream.getNextEntry();

                    // Iterate over the entries and extract the selected files
                    while (entry != null) {
                        if (entry.getName().equals(selectedFileName)) {
                            String filePath = destDirectory + File.separator + entry.getName();
                            if (!entry.isDirectory()) {
                                extractFile(zipStream, filePath);
                            } else {
                                // Create the directory if it does not exist
                                File directory = new File(filePath);
                                directory.mkdirs();
                            }
                        }

                        zipStream.closeEntry();
                        entry = zipStream.getNextEntry();
                    }
                }
            }
        }

        File file = new File(Application.getMyModuleRootDirectory().getAbsolutePath()+"/data/all_files.zip");
        file.delete();
        System.out.println("Files downloaded successfully.");
    }
    
    private void extractFile(ZipInputStream zipStream, String filePath) throws IOException {
    	
        try (BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(filePath))) {
            byte[] buffer = new byte[4096];
            int bytesRead = -1;
            while ((bytesRead = zipStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    private void updateOpenFiDbFiles(){
        List<ResourceFile> resourceFiles = Application.findFilesByExtensionInMyModule(".fidb");
        openFiDbFiles = new ArrayList<>();
        resourceFiles.forEach(resourceFile -> openFiDbFiles.add(resourceFile.getFile(false)));
        openFiDbFilesNames = new ArrayList<>();
        openFiDbFiles.forEach(dbFile -> openFiDbFilesNames.add(dbFile.getName()));
    }
    
    private void disableActions() {
    	loginAction.setEnabled(true);
    	logoutAction.setEnabled(false);
        pullAction.setEnabled(false);
        pushAction.setEnabled(false);
        deleteAction.setEnabled(false);
        discardAction.setEnabled(false);
    }

    private void enableActions() {
    	loginAction.setEnabled(false);
    	logoutAction.setEnabled(true);
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

