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

import com.google.gson.Gson;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.io.OutputStream;
import java.io.FileInputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import javax.swing.JList;
import javax.swing.DefaultListModel;

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


public class OpenFunctionIDPlugin extends ProgramPlugin{

	private static final String FUNCTION_ID_NAME = "Function ID";
    private static final String MENU_GROUP_1 = "group1";
    private static final String MENU_GROUP_2 = "group2";
    //private static final String REPO_URL = "https://github.com/Cyjanss/OpenFiDb.git";
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
    private DockingAction logoutAction;
    private DockingAction populateAction;
    private DockingAction removeAction;
    private String responseString;
    
    private List<JCheckBox> checkboxes = new ArrayList<>();

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
        //pullAction.setEnabled(false);
        pushAction.setEnabled(false);
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
            	LoginDialog login = new LoginDialog(loginAction,pullAction,pushAction,deleteAction,logoutAction,removeAction,populateAction);
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "login"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Login"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        loginAction = action;
        
        //remove
        action = new DockingAction("delete function", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
            	try {
					removeRequest(LoginDialog.getUserId());
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
            }
        };
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "remove"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "remove"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
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
        action = new DockingAction("Populate DB", getName()) {
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
        action.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME, "Populate DB"));
        action.setMenuBarData(new MenuData(
                new String[]{ToolConstants.MENU_TOOLS, FUNCTION_ID_NAME, OpenFunctionIDPackage.NAME,
                        "Populate DB"},
                null, MENU_GROUP_1, MenuData.NO_MNEMONIC, "1"));
        this.tool.addAction(action);
        populateAction = action;
        
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
					pullRequest();
					/*updateOpenFiDbFiles();
			        attachAll();
			        chooseActive();*/
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
        System.out.println(LoginDialog.getUserId());
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
    
    private void show(Selection dialog) {
    	tool.showDialog(dialog);
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
    
    public boolean removeRequest(String user) throws Exception {
        URL url = new URL(POST_URL + "get_remove/" + user);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        System.out.println("Response code: " + responseCode);

        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        System.out.println(response.toString());

        Gson gson = new Gson();
        Object[] items = gson.fromJson(response.toString(), Object[].class);

        DefaultListModel<Object> listModel = new DefaultListModel<>();
        listModel.addAll(Arrays.asList(items));
        JList<Object> jList = new JList<>(listModel);

        jList.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    Object selectedItem = jList.getSelectedValue();
                }
            }
        });

        int result = JOptionPane.showConfirmDialog(null, jList, "Select item to remove", JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            Object selectedItem = jList.getSelectedValue();
            deleteSelectedItem(selectedItem.toString());
        }

        return true;
    }
    
    public boolean deleteSelectedItem(String item) throws Exception {
    	URL obj = new URL(POST_URL + "delete_selected");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);
        String userfrom = LoginDialog.getUserId();
        String payload = String.format("{\"item\":\"%s\"}", item);
        
        OutputStream os = con.getOutputStream();
        os.write(payload.getBytes());
        os.flush();
        os.close();
        
        int responseCode = con.getResponseCode();
		if (responseCode == HttpURLConnection.HTTP_OK) {
		    BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
		    String inputLine;
		    StringBuilder response = new StringBuilder();
		    while ((inputLine = in.readLine()) != null) {
		        response.append(inputLine);
		    }
		    in.close();
		    String regmessage = response.toString();
		    
		    if(response.toString().contains("Success!")) {
		    	JOptionPane.showMessageDialog(null, regmessage);
            	return true;
            }
		    else {
		    	return false;
		    }  
		    
		}
		else {
			System.out.println("POST request did not work.");
        	return false;
		}
    }
    
    public boolean pullRequest() throws Exception {
    	URL url = new URL(POST_URL + "download_files");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        System.out.println("Response code: " + responseCode);

        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();
        
        String[] parts = response.toString().split("(?<=]),"); // split by "]," and keep delimiter
        List<List<String>> result = new ArrayList<>();

        for (String part : parts) {
            String[] subparts = part.split(",(?=\\[)"); // split by "," followed by "[" and discard delimiter
            List<String> sublist = new ArrayList<>();
            for (String subpart : subparts) {
                sublist.add(subpart.replaceAll("\\[|\\]", "").trim()); // remove brackets and whitespace
            }
            result.add(sublist);
        }
        
    	String fileName = "MainDatabase.c";

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
        	
            System.out.println(field[0]);
            System.out.println(field[1]);
            System.out.println(field[2]);
            System.out.println(field[3]);
            System.out.println(field[4]);
            System.out.println(field[5]);
            System.out.println(field[6]);
            System.out.println(field[7]);
            System.out.println(field[8]);
            System.out.println(field[9]);
            System.out.println(field[10]);
            System.out.println(field[11]);
            System.out.println(field[12]);
            System.out.println(field[13]);
            System.out.println(field[14]);
            System.out.println(field[15]);
            
            MyItem item = new MyItem(user, Short.parseShort(codeUnitSize.trim()), Long.parseLong(fullHash.trim()), 
            						Byte.parseByte(specificHashAdditionalSize.trim()), Long.parseLong(specificHash.trim()), 
            						library_name, library_version, 
            						library_variant, Ghidraversion, new LanguageID(Languageid), 
            						Integer.parseInt(Languageversion.trim()), Integer.parseInt(Languageminorversion.trim()),
            						new CompilerSpecID(Compilerspecid), funName, Long.parseLong(Entrypoint.trim()), Codec);
            output.add(item);

        }
        Selection dialog = new Selection(output,false);
        tool.showDialog(dialog);
        return true;
    }
    
    
    private void updateOpenFiDbFiles(){
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
        pushAction.setEnabled(false);
        deleteAction.setEnabled(false);
        removeAction.setEnabled(false);
    }

    private void enableActions() {
    	loginAction.setEnabled(false);
    	logoutAction.setEnabled(true);
        populateAction.setEnabled(true);
        pullAction.setEnabled(true);
        pushAction.setEnabled(true);
        deleteAction.setEnabled(true);
        removeAction.setEnabled(true);
    }

    /*
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
    }*/
    private void println(String s){
        OpenFunctionIDPackage.println(tool,"[OpenFunctionID] "+s);
    }
}

