package openfunctionid;

import docking.DialogComponentProvider;
import docking.action.ToolBarData;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.label.GLabel;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.actions.ExportToCAction;
import ghidra.app.script.SelectLanguageDialog;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class OpenFunctionIDUploadC extends ExportToCAction {

    String codeC;

    /**
     * Server is not up, the community dataset and users contributions are not available
     */
    private static boolean connected = false;
    
    public static void setConnected(boolean co) {
    	connected = co;
    }

    OpenFunctionIDUploadC() {
        super();
        super.setToolBarData(new ToolBarData(ResourceManager.loadImage(OpenFunctionIDPackage.OPENFIDB_ICON), "Local"));
        super.setDescription("Upload decompiled c to OpenFiDb");
        super.setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME,"upload"));
    }

    @Override
    protected void decompilerActionPerformed(DecompilerActionContext context) {
        if (!connected){
            Msg.showInfo(getClass(),null,"Not connected yet","Since OpenFunctionID need to authenticate, users need to be connected.");
            return;
        }else if (!getCCode(context)) {
            return;
        }
        SendToOpenFiDbDialog sendToOpenFiDbDialog = new SendToOpenFiDbDialog(context, codeC);
        context.getTool().showDialog(sendToOpenFiDbDialog);
    }

    private boolean getCCode(DecompilerActionContext context) {
        ClangTokenGroup grp = context.getCCodeModel();
        PrettyPrinter printer = new PrettyPrinter(context.getFunction(), grp);
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
    private JTextField libraryFamilyNameTextField;
    private JTextField versionTextField;
    private JTextField variantTextField;
    private JTextField languageIdField;

    protected SendToOpenFiDbDialog(DecompilerActionContext context, String codeC) {
        super("Send to OpenFiDb");
        this.context = context;
        this.codeC = codeC;
        addWorkPanel(buildMainPanel());
        addOKButton();
        addCancelButton();
        updateOkEnablement();
        setRememberSize(false);
        setHelpLocation(new HelpLocation(OpenFunctionIDPackage.HELP_NAME,"upload"));

    }

    private JComponent buildMainPanel() {
        JPanel panel = new JPanel(new PairLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        panel.add(new GLabel("Library Family Name: ", SwingConstants.RIGHT));
        libraryFamilyNameTextField = new JTextField(20);
        libraryFamilyNameTextField.getDocument().addUndoableEditListener(e -> updateOkEnablement());
        panel.add(libraryFamilyNameTextField);

        panel.add(new GLabel("Library Version: ", SwingConstants.RIGHT));
        versionTextField = new JTextField();
        versionTextField.getDocument().addUndoableEditListener(e -> updateOkEnablement());
        panel.add(versionTextField);

        panel.add(new GLabel("Library Variant: ", SwingConstants.RIGHT));
        variantTextField = new JTextField();
        variantTextField.getDocument().addUndoableEditListener(e -> updateOkEnablement());
        panel.add(variantTextField);

        panel.add(new GLabel("Language: ", SwingConstants.RIGHT));
        panel.add(buildLanguageField());

        return panel;
    }

    private Component buildLanguageField() {
        JPanel panel = new JPanel(new BorderLayout());
        languageIdField = new JTextField();
        panel.add(languageIdField, BorderLayout.CENTER);
        JButton browseButton = createBrowseButton();
        browseButton.addActionListener(e -> {
            SelectLanguageDialog selectLanguageDialog =
                    new SelectLanguageDialog("Select Language", "Ok");
            //DockingWindowManager.showDialog(null, selectLanguageDialog);//Replacement
            //selectLanguageDialog.show();
            LanguageCompilerSpecPair selectedLanguage = selectLanguageDialog.getSelectedLanguage();
            if (selectedLanguage != null) {
                languageIdField.setText(selectedLanguage.languageID.toString());
            }
        });
        languageIdField.getDocument().addUndoableEditListener(e -> updateOkEnablement());
        panel.add(browseButton, BorderLayout.EAST);
        return panel;

    }

    private JButton createBrowseButton() {
        JButton browseButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
        Font font = browseButton.getFont();
        browseButton.setFont(new Font(font.getName(), Font.BOLD, font.getSize()));
        return browseButton;
    }

    @Override
    protected void okCallback() {
        String libraryFamilyName = libraryFamilyNameTextField.getText().trim();
        String libraryVersion = versionTextField.getText().trim();
        String libraryVariant = variantTextField.getText().trim();
        String languageFilter = languageIdField.getText().trim();
        close();
        Msg.showInfo(getClass(), context.getDecompilerPanel(), "Code to upload from " + LoginDialog.getUserId(), codeC);
        Task task = new SendToOpenFiDb("SendToOpenFiDb", libraryFamilyName,
                libraryVersion, libraryVariant, languageFilter, codeC);
        context.getTool().execute(task);
    }

    private void updateOkEnablement() {
        setOkEnabled(isUserInputComplete());
    }

    private boolean isUserInputComplete() {
        if (libraryFamilyNameTextField.getText().trim().isEmpty()) {
            return false;
        }
        if (versionTextField.getText().trim().isEmpty()) {
            return false;
        }
        if (variantTextField.getText().trim().isEmpty()) {
            return false;
        }
        return !languageIdField.getText().trim().isEmpty();
    }
}

class SendToOpenFiDb extends Task {

    private static final String POST_URL = "http://127.0.0.1:5000/";

	private final String libraryFamilyName;
    private final String libraryVersion;
    private final String libraryVariant;
    private final String languageId;
    private final String codeC;

    protected SendToOpenFiDb(String title, String libraryFamilyName, String libraryVersion,
                             String libraryVariant, String languageId, String codeC) {
        super(title);
        this.libraryFamilyName = libraryFamilyName;
        this.libraryVersion = libraryVersion;
        this.libraryVariant = libraryVariant;
        this.languageId = languageId;
        this.codeC = codeC;
    }

    @Override
    public void run(TaskMonitor monitor) throws CancelledException {
    	String response = "";
        try {
        	
            URL url = new URL(POST_URL + "send_file");


            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setRequestProperty("unique_id", LoginDialog.getUserId());
            connection.setRequestProperty("libraryFamilyName", libraryFamilyName);
            connection.setRequestProperty("libraryVersion", libraryVersion);
            connection.setRequestProperty("libraryVariant", libraryVariant);
            connection.setRequestProperty("languageId", languageId);
            connection.setRequestProperty("codeC", Base64.getEncoder().encodeToString(codeC.getBytes(StandardCharsets.UTF_8)));
            connection.setDoOutput(true);
			System.out.println(connection.getResponseCode());

			if(connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
				InputStream con = connection.getInputStream();
	            Reader result = new BufferedReader(new InputStreamReader(con, StandardCharsets.UTF_8));

	            StringBuilder sb = new StringBuilder();
	            for (int c; (c = result.read()) >= 0; ) {
	                sb.append((char) c);
	            }
	            response = sb.toString();
	            Msg.showInfo(getClass(), null, "Function uploaded", response);

			}
			if(connection.getResponseCode() == HttpURLConnection.HTTP_CONFLICT) {
	            InputStream con = connection.getErrorStream();
	            Reader result = new BufferedReader(new InputStreamReader(con, StandardCharsets.UTF_8));

	            StringBuilder sb = new StringBuilder();
	            for (int c; (c = result.read()) >= 0; ) {
	                sb.append((char) c);
	            }
	            response = sb.toString();
	            Msg.showError(getClass(), null, "Conflict when sending data", response);

			}
            
        } catch (IOException e) {
        	
            Msg.showError(getClass(), null, "Error when sending data", "Error when sending data to OpenFiDb", e);
            throw new CancelledException("Error when sending data to OpenFiDb");
        }
    }
}
