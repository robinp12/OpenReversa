package openfunctionid;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import java.awt.Font;
import java.awt.Window;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JDialog;
import javax.swing.JLabel;

import docking.DialogComponentProvider;
import ghidra.feature.fid.db.FidDB;
import ghidra.feature.fid.db.FunctionRecord;
import ghidra.feature.fid.db.FunctionsTable;
import ghidra.feature.fid.db.LibraryRecord;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.plugin.FidPlugin;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class Selection extends DialogComponentProvider {

    private ArrayList<MyItem> output;
    private boolean isPush;
    private List<JCheckBox> checkboxes = new ArrayList<>();
    private static String regmessage = "";
    private FidDB fidDb = null;
    Request request = new Request();
    private TaskMonitor monitor = new TaskMonitorAdapter();


    public Selection(ArrayList<MyItem> output, boolean isPush) {
        super("Select Functions (Double click to see entire function)", false);

        this.output = new ArrayList<>(output);
        this.isPush = isPush;
        addWorkPanel(buildMainPanel());
        addOKButton();
        setDefaultButton(okButton);
        if (isPush) {
        	setOkButtonText("Push function(s)");
        }else {
        	setOkButtonText("Pull function(s)");
        }
        setRememberSize(false);
        setPreferredSize(400, 400);
        setHelpLocation(new HelpLocation(FidPlugin.FID_HELP, "chooseactivemenu"));
    }

    protected void okCallback() {
        StringBuilder sb = new StringBuilder();
        
        if (!isPush) {
            CreateNewFidDatabase rrf = new CreateNewFidDatabase();
            try {
                fidDb = rrf.selectFidFile();
            } catch (CancelledException | VersionException | IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
            monitor.initialize(1);
        }
        
        int checkIfSelected = 0;
        for (JCheckBox checkbox : checkboxes) {
            if (checkbox.isSelected()) {
            	checkIfSelected += 1;
            	String itemName = Base64.getEncoder().encodeToString(checkbox.getText().getBytes(StandardCharsets.UTF_8));
            	
            	System.out.println(itemName);
                MyItem selected = output.stream()
                        .filter(item -> item.getSignature().equals(itemName))
                        .findFirst().orElse(null);
                if (isPush) {
                    try {
                        boolean push = request.sendToDBrequest(selected.getCodeUnitSize(), selected.getFullHash(), selected.getSpecificHashAdditionalSize(),
                                selected.getSpecificHash(), selected.getLibraryFamilyNameTextField(), selected.getVersionTextField(),
                                selected.getVariantTextField(), selected.getApp_version(),
                                selected.getLang_id(), selected.getLang_ver(),
                                selected.getLang_minor_ver(), selected.getCompiler_spec(),
                                selected.getFun_name(), selected.getFun_entry(), selected.getSignature(), selected.getTokgroup());
		                        
                        JDialog dialog = (JDialog) SwingUtilities.getWindowAncestor(getComponent());
                        dialog.getRootPane().setDefaultButton(okButton);
		                        dialog.dispose();
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                    	Msg.showError(getClass(), null, "Server error", "Sorry, the server is currently unavailable. Please try again later.");
                        e.printStackTrace();
                    }
                    if (selected != null) {
                        sb.append(selected.getSignature()).append(": ").append(selected.getFullHash()).append("\n");
                    }
                } else {
                	System.out.println(selected.getSignature());
                    try {
                        if (fidDb != null) {
                            FunctionsTable ft = new FunctionsTable(fidDb, fidDb != null ? fidDb.getDBHandle() : null);
                            int sizeFun = ft.getFunctionRecordsByFullHash(selected.getFullHash()).size();
                            System.out.println("ici: \n" + ft.getFunctionRecordsByFullHash(selected.getFullHash()).size());
                            if (sizeFun == 0) {
                                LibraryRecord newlib = fidDb.createNewLibrary(selected.getLibraryFamilyNameTextField(),
                                        selected.getVersionTextField(), selected.getVariantTextField(),
                                        selected.getApp_version(), selected.getLang_id(), selected.getLang_ver(),
                                        selected.getLang_minor_ver(), selected.getCompiler_spec());

                                FidHashQuad hashQuad = new FidHashQuadImpl(selected.getCodeUnitSize(),
                                        selected.getFullHash(), selected.getSpecificHashAdditionalSize(),
                                        selected.getSpecificHash());

                                FunctionRecord newfunc = fidDb.createNewFunction(newlib, hashQuad,
                                        selected.getFun_name(), selected.getFun_entry(), "", false);

                                fidDb.saveDatabase("Saving", monitor);

                            }
                        }
                        JDialog dialog = (JDialog) SwingUtilities.getWindowAncestor(getComponent());
                        dialog.dispose();


                    } catch (CancelledException | IOException e1) {
                        // TODO Auto-generated catch block
                    	Msg.showError(getClass(), null, "Server error", "Sorry, the server is currently unavailable. Please try again later.");
                    	e1.printStackTrace();
                    }
                    if (selected != null) {
                        sb.append(selected.getSignature()).append(": ").append(selected.getFullHash()).append("\n");
                    }
                }
            }
        
        }if (checkIfSelected == 0){
        	JOptionPane.showMessageDialog(null,
        			"Please select one or more function(s) to continue.",
                    "Error in selection",
                    JOptionPane.ERROR_MESSAGE);
        }
    }

    private JComponent buildMainPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        panel.add(buildCheckboxPanelScroller(), BorderLayout.CENTER);
        panel.add(buildButtonPanel(), BorderLayout.SOUTH);
        return panel;
    }

    private Component buildButtonPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton allButton = new JButton("Select All");
        JButton noneButton = new JButton("Select None");
        allButton.addActionListener(e -> selectAllCheckboxes(true));
        noneButton.addActionListener(e -> selectAllCheckboxes(false));
        panel.add(allButton);
        panel.add(noneButton);
        return panel;
    }

    private void selectAllCheckboxes(boolean b) {
        for (JCheckBox jCheckBox : checkboxes) {
            jCheckBox.setSelected(b);
        }
    }

    private Component buildCheckboxPanelScroller() {
        JScrollPane scrollPane;
        if (isPush) {
            scrollPane = new JScrollPane(buildCheckBoxPanelPush());
        } else {
            scrollPane = new JScrollPane(buildCheckBoxPanelPull());
        }
        return scrollPane;
    }

    private Component buildCheckBoxPanelPush() {
        JPanel panel = new JPanel(new VerticalLayout(5));
        panel.setOpaque(true);
        panel.setBackground(Color.WHITE);
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        for (MyItem items : output) {
            System.out.println("ici: \n" + new String(Base64.getDecoder().decode(items.getSignature()), StandardCharsets.UTF_8));
            JCheckBox checkbox = new JCheckBox(new String(Base64.getDecoder().decode(items.getSignature()), StandardCharsets.UTF_8));
            checkboxes.add(checkbox);
            panel.add(checkbox);
        }
        return panel;
    }

    private Component buildCheckBoxPanelPull() {
        JPanel panel = new JPanel(new VerticalLayout(5));
        panel.setOpaque(true);
        panel.setBackground(Color.WHITE);
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        RetrieveRenamedFunction rrf = new RetrieveRenamedFunction();
		LanguageID langId = rrf.getProgramLanguage();
        
        for (MyItem items : output) {
			
			if(items.getLang_id().equals(langId)){
	            System.out.println("ici: \n" + new String(Base64.getDecoder().decode(items.getSignature()), StandardCharsets.UTF_8));

			    JCheckBox checkbox = new JCheckBox(new String(Base64.getDecoder().decode(items.getSignature()), StandardCharsets.UTF_8));
			    checkbox.addMouseListener(new MouseAdapter() {
			        public void mouseClicked(MouseEvent e) {
			            if (e.getClickCount() == 2) {
			                JTextArea textArea = new JTextArea(new String(Base64.getDecoder().decode(items.getTokgroup().trim()), StandardCharsets.UTF_8));
			                textArea.setLineWrap(true);
			                textArea.setWrapStyleWord(true);
			                textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
			            JScrollPane scrollPane = new JScrollPane(textArea);
			            scrollPane.setPreferredSize(new Dimension(500, 300));
			            JPanel messagePanel = new JPanel(new BorderLayout());
			            messagePanel.add(scrollPane, BorderLayout.CENTER);
			
			            JPanel buttonPanel = new JPanel(new FlowLayout());
			            if (items.getUser().equals(LoginDialog.getUserId())) {
			                JButton deleteButton = new JButton("Remove function from database");
			                deleteButton.addActionListener(new ActionListener() {
			                    @Override
			                    public void actionPerformed(ActionEvent e) {
			                        try {
			                        	boolean delete = request.deleteSelectedItem(items.getSignature());
		                                if (delete) {
				                            output.remove(items);
				
				                            panel.remove(checkbox);
				                            panel.revalidate();
				                            panel.repaint();
				
				                            Window window = SwingUtilities.getWindowAncestor(buttonPanel);
				                            if (window instanceof JDialog) {
				                                JDialog dialog = (JDialog) window;
				                                dialog.dispose();
				                            }
		                                }
			                            
			                        } catch (Exception e1) {
			                            // TODO Auto-generated catch block
			                        	Msg.showError(getClass(), null, "Server error", "Sorry, the server is currently unavailable. Please try again later.");
			                            e1.printStackTrace();
			                        }
			                    }
			                });
			                buttonPanel.add(deleteButton);
			            } else {
			
			                JButton discussionButton = new JButton("Send a discussion request");
			                discussionButton.addActionListener(new ActionListener() {
			                    @Override
			                    public void actionPerformed(ActionEvent e) {
			                        JDialog dialog = new JDialog();
			                        dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
			                        dialog.setModal(true);
			                        dialog.addWindowListener(new WindowAdapter() {
			                            @Override
			                            public void windowDeactivated(WindowEvent e) {
			                                dialog.requestFocus();
			                            }
			                        });
			                        int choice = JOptionPane.showConfirmDialog(dialog, "Are you sure you want to send a discussion request ? This will send your email address to the user in question", "Confirmation", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
			                        if (choice == JOptionPane.YES_OPTION) {
			                            try {
			                            	boolean discuss = request.discuss(items);
			                            	System.out.println(discuss);
			                                if (discuss) {
			                                	JOptionPane.showMessageDialog(null, "Discussion request sent successfully");
			                                }
			                            } catch (IOException e1) {
			                            	Msg.showError(getClass(), null, "Server error", "Sorry, the server is currently unavailable. Please try again later.");
			                                e1.printStackTrace();
			                            }
			                        }
			                    }
			                });
			                buttonPanel.add(discussionButton);
			
			                JButton reportButton = new JButton("Report function");
			                reportButton.addActionListener(new ActionListener() {
			                    @Override
			                    public void actionPerformed(ActionEvent e) {
			                        JDialog dialog = new JDialog();
			                        dialog.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
			                        dialog.setModal(true);
			                        dialog.addWindowListener(new WindowAdapter() {
			                            @Override
			                            public void windowDeactivated(WindowEvent e) {
			                                dialog.requestFocus();
			                            }
			                        });
			                        int choice = JOptionPane.showConfirmDialog(null, "Are you sure you want to report this user ?", "Confirmation", JOptionPane.YES_NO_OPTION);
			                        if (choice == JOptionPane.YES_OPTION) {
			                            try {
			                                boolean report = request.report(items);
			                                if (report) {
			                                	JOptionPane.showMessageDialog(null, "Report successfully sent");
			                                }
			                            } catch (IOException e1) {
			                            	Msg.showError(getClass(), null, "Server error", "Sorry, the server is currently unavailable. Please try again later.");
			                                e1.printStackTrace();
			                            }
			                        }
			                    }
			                });
			                buttonPanel.add(reportButton);
			            }
			
			            messagePanel.add(buttonPanel, BorderLayout.SOUTH);
			
			            JOptionPane.showMessageDialog(null, messagePanel, "Function Overview", JOptionPane.PLAIN_MESSAGE);
			            }
			        }
			    });
			    checkboxes.add(checkbox);
			    panel.add(checkbox);
			}
        }
        return panel;
    }

}
