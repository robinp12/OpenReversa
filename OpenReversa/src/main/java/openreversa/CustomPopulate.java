package openreversa;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

//TODO write a description for this script
//@author Arnaud Delcorte and Robin Paquet
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
import ghidra.feature.fid.service.FidPopulateResult;
import ghidra.feature.fid.service.FidPopulateResultReporter;
import ghidra.feature.fid.service.Location;
import ghidra.feature.fid.service.FidPopulateResult.Disposition;
import ghidra.util.layout.PairLayout;

public class CustomPopulate extends GhidraScript {
    // Define GUI components
    private JTextField libraryFamilyNameTextField;
    private JTextField versionTextField;
    private JTextField variantTextField;
    private JTextField langTextField;
    private JButton okBtn;

    // Method for taking input from the user using a dialog
    public void libraryInput() {
        JDialog dialog = new JDialog();
        dialog.setModal(true);
        dialog.setLocationRelativeTo(null); // center the dialog on the screen
        JPanel panel1 = new JPanel(new PairLayout());

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
        dialog.getRootPane().setDefaultButton(okBtn);

        // Action listener for the "Confirm" button
        okBtn.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (isUserInputComplete()) {
                    dialog.dispose();
                    new RetrieveRenamedFunction(
                            libraryFamilyNameTextField.getText().trim(),
                            versionTextField.getText().trim(),
                            variantTextField.getText().trim());
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

    // Method to check if the user input is complete
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

	@Override
	protected void run() throws Exception {
		// TODO Auto-generated method stub
		
	}
}