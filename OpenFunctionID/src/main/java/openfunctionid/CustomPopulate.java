package openfunctionid;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

//TODO write a description for this script
//@author Zina Rasoamanana 
//@category test
//@keybinding 
//@menupath 
//@toolbar test.png


//Headless
import java.util.*;
import java.util.Map.Entry;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

import docking.widgets.label.GLabel;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.*;
import ghidra.feature.fid.plugin.IngestTask;
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidPopulateResultReporter;
import ghidra.feature.fid.service.FidService;
import ghidra.feature.fid.service.Location;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitorAdapter;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.PairLayout;

public class CustomPopulate extends GhidraScript {
    private JTextField libraryFamilyNameTextField;
    private JTextField versionTextField;
    private JTextField variantTextField;
    private JTextField langTextField;

    private FidService fidService;
    private JButton okBtn;

    public void libraryInput() {

        JDialog dialog = new JDialog();
        dialog.setModal(true);
        dialog.setLocationRelativeTo(null); // center the dialog on the screen

        JPanel panel1 = new JPanel(new PairLayout());
        JPanel panel2 = new JPanel(new BorderLayout());

        dialog.setSize(300, 150);
        dialog.setResizable(false);
        dialog.setTitle("Share your function with others");
        panel1.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));


        panel1.add(new GLabel("Library Family Name: ", SwingConstants.RIGHT));
        libraryFamilyNameTextField = new JTextField(20);
        panel1.add(libraryFamilyNameTextField);

        panel1.add(new GLabel("Library Version: ", SwingConstants.RIGHT));
        versionTextField = new JTextField(20);
        panel1.add(versionTextField);

        panel1.add(new GLabel("Library Variant: ", SwingConstants.RIGHT));
        variantTextField = new JTextField(20);
        panel1.add(variantTextField);

        panel1.add(new GLabel("Language ID: ", SwingConstants.RIGHT));
        langTextField = new JTextField(20);
        RetrieveRenamedFunction rrf = new RetrieveRenamedFunction();
        langTextField.setText(rrf.getProgramLanguage().toString());
        langTextField.setEnabled(false);
        panel1.add(langTextField);

        okBtn = new JButton("Confirm");

        okBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (isUserInputComplete()) {
                    new RetrieveRenamedFunction(
                            libraryFamilyNameTextField.getText().trim(),
                            versionTextField.getText().trim(),
                            variantTextField.getText().trim());
                    dialog.dispose();
                }

            }
        });

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(okBtn);

        dialog.getContentPane().add(panel1, java.awt.BorderLayout.CENTER);
        dialog.getContentPane().add(buttonPanel, java.awt.BorderLayout.PAGE_END);

        dialog.setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);
        dialog.pack();
        dialog.setLocationRelativeTo(null);
        dialog.setVisible(true);
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
        return true;
    }

    protected void run() throws Exception {
    }
}

class MyFidPopulateResultReporter implements FidPopulateResultReporter {
    @Override
    public void report(FidPopulateResult result) {
        if (result == null) {
            return;
        }
        LibraryRecord libraryRecord = result.getLibraryRecord();
        String libraryFamilyName = libraryRecord.getLibraryFamilyName();
        String libraryVersion = libraryRecord.getLibraryVersion();
        String libraryVariant = libraryRecord.getLibraryVariant();
        outputLine(libraryFamilyName + ':' + libraryVersion + ':' + libraryVariant);

        outputLine(result.getTotalAttempted() + " total functions visited");
        outputLine(result.getTotalAdded() + " total functions added");
        outputLine(result.getTotalExcluded() + " total functions excluded");
        outputLine("Breakdown of exclusions:");
        for (Entry<Disposition, Integer> entry : result.getFailures().entrySet()) {
            if (entry.getKey() != Disposition.INCLUDED) {
                outputLine("    " + entry.getKey() + ": " + entry.getValue());
            }
        }
        outputLine("List of unresolved symbols:");
        TreeSet<String> symbols = new TreeSet<>();
        for (Location location : result.getUnresolvedSymbols()) {
            symbols.add(location.getFunctionName());
        }
        for (String symbol : symbols) {
            outputLine("    " + symbol);
        }
    }

    protected void outputLine(String line) {
        System.out.println(line);
    }

}
