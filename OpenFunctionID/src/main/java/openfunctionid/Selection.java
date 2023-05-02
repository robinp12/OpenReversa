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
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import java.io.BufferedReader;
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

import docking.DialogComponentProvider;
import docking.widgets.checkbox.GCheckBox;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.feature.fid.db.FidFile;
import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.plugin.FidPlugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.layout.VerticalLayout;

public class Selection extends DialogComponentProvider{
	
	private ArrayList<MyItem> output;
	private boolean verif;
	private List<JCheckBox> checkboxes = new ArrayList<>();
	private static final String POST_URL = "http://127.0.0.1:5000/";
	private static String regmessage = "";

	public Selection(ArrayList<MyItem> output, boolean verif) {
		super("Select Files", false);

	    this.output = new ArrayList<>(output);
	    this.verif = verif;
	    addWorkPanel(buildMainPanel());
	    addOKButton();
	    setOkButtonText("Dismiss");
	    setRememberSize(false);
	    setPreferredSize(400, 400);
	    setHelpLocation(new HelpLocation(FidPlugin.FID_HELP, "chooseactivemenu"));
	    
	}
	
	protected void okCallback() {
	    StringBuilder sb = new StringBuilder();
	    for (JCheckBox checkbox : checkboxes) {
	        if (checkbox.isSelected()) {
	            String itemName = checkbox.getText();
	            MyItem selected = output.stream()
	                    .filter(item -> item.getFun_name().equals(itemName))
	                    .findFirst().orElse(null);
	            if (verif) {
		            try {
						sendPOST(selected.getFullHash(), selected.getLibraryFamilyNameTextField(), selected.getVersionTextField(),
	selected.getVariantTextField(), selected.getApp_version(), 
	selected.getLang_id(), selected.getLang_ver(),
	selected.getLang_minor_ver(), selected.getCompiler_spec(),
	selected.getHashFunction(), selected.getFun_name(), 
	selected.getFun_entry(), selected.getTokgroup());
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
		           
		            if (selected != null) {
		                sb.append(selected.getFun_name()).append(": ").append(selected.getFullHash()).append("\n");
		            }
	            }
	        }
	    }
	    System.out.println("Selected items: \n" + sb.toString());

	    JDialog dialog = (JDialog) SwingUtilities.getWindowAncestor(getComponent());
	    dialog.dispose();
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
		scrollPane = new JScrollPane(buildCheckBoxPanelPush());
		return scrollPane;
	}
	
	private Component buildCheckBoxPanelPush() {
	    JPanel panel = new JPanel(new VerticalLayout(5));
	    panel.setOpaque(true);
	    panel.setBackground(Color.WHITE);
	    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
	    for (MyItem items : output) {
	    	JCheckBox checkbox = new JCheckBox(items.getFun_name());
	    	checkboxes.add(checkbox);
	        panel.add(checkbox);
	    }
		return panel;
	}

	/*private Component buildCheckBoxPanel() {
	    JPanel panel = new JPanel(new VerticalLayout(5));
	    panel.setOpaque(true);
	    panel.setBackground(Color.WHITE);
	    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
	    for (MyItem items : output) {
	        JCheckBox checkbox = new JCheckBox(items.getFun_name());
	        checkbox.addMouseListener(new MouseAdapter() {
	            public void mouseClicked(MouseEvent e) {
	                if (e.getClickCount() == 2) {
	                    JTextArea textArea = new JTextArea(items.getHashFunction());
	                    textArea.setLineWrap(true);
	                    textArea.setWrapStyleWord(true);
	                    textArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
	                    JScrollPane scrollPane = new JScrollPane(textArea);
	                    scrollPane.setPreferredSize(new Dimension(500, 300));
	                    JPanel messagePanel = new JPanel(new BorderLayout());
	                    messagePanel.add(scrollPane, BorderLayout.CENTER);
	                    
	                    JPanel buttonPanel = new JPanel(new FlowLayout());
	                    if (items.getInfo2().equals(LoginDialog.getUserId())) {
	                    	JButton deleteButton = new JButton("delete function");
		                    deleteButton.addActionListener(new ActionListener() {
		                        @Override
		                        public void actionPerformed(ActionEvent e) {
		                            try {
										deleteSelectedItem(items.getName());
										output.remove(items);
			
							            panel.remove(checkbox);
							            panel.revalidate();
							            panel.repaint();
							            
							            Window window = SwingUtilities.getWindowAncestor(buttonPanel);
							            if (window instanceof JDialog) {
							                JDialog dialog = (JDialog) window;
							                dialog.dispose();
							            }
									} catch (Exception e1) {
										// TODO Auto-generated catch block
										e1.printStackTrace();
									}
		                            System.out.println("fonction supprimée");
		                        }
		                    });
		                    buttonPanel.add(deleteButton);
	                    }else {
		                    JButton discussionButton = new JButton("Send a discussion request");
		                    discussionButton.addActionListener(new ActionListener() {
		                        @Override
		                        public void actionPerformed(ActionEvent e) {
		                            try {
		                                discuss(items.getInfo2());
		                            } catch (IOException e1) {
		                                e1.printStackTrace();
		                            }
		                            JOptionPane.showMessageDialog(null, "Discussion request sent successfully");
		                            System.out.println("Message envoyé");
		                        }
		                    });
		                    buttonPanel.add(discussionButton);
		                    
		                    JButton reportButton = new JButton("report");
		                    reportButton.addActionListener(new ActionListener() {
		                        @Override
		                        public void actionPerformed(ActionEvent e) {
		                            try {
		                                report(items.getInfo2());
		                            } catch (IOException e1) {
		                                e1.printStackTrace();
		                            }
		                            JOptionPane.showMessageDialog(null, "report request sent successfully");
		                            System.out.println("Message signalé");
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
	    return panel;
	}*/
	
	private static boolean discuss(String userto) throws IOException {
		URL obj = new URL(POST_URL + "discuss");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);
        String userfrom = LoginDialog.getUserId();
        String payload = String.format("{\"userto\":\"%s\",\"userfrom\":\"%s\"}", userto, userfrom);
        
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
		    regmessage = response.toString();
		    
		    if(response.toString().contains("Success!")) {
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
		
	private static boolean report(String userto) throws IOException {
		URL obj = new URL(POST_URL + "report");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);
        String userfrom = LoginDialog.getUserId();
        String payload = String.format("{\"userto\":\"%s\",\"userfrom\":\"%s\"}", userto, userfrom);
        
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
		    regmessage = response.toString();
		    
		    if(response.toString().contains("Success!")) {
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
	
	private void sendPOST(long fullHash, String libraryFamilyName, String libraryVersion,
			String libraryVariant, String ghidraVersion, 
			LanguageID languageID, int languageVersion,
			int languageMinorVersion, CompilerSpecID compilerSpecID,
			FidHashQuad hashQuad, String funName, 
			long entryPoint, ClangTokenGroup tokgroup) throws IOException {

		URL url = new URL(POST_URL + "fid");
		String response = "";
		
		HttpURLConnection connection = (HttpURLConnection) url.openConnection();
		connection.setRequestMethod("POST");
		connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		
		connection.setRequestProperty("fullHash", Long.toString(fullHash));
		
		connection.setRequestProperty("unique_id", LoginDialog.getUserId());
		connection.setRequestProperty("libraryFamilyName", libraryFamilyName);
		connection.setRequestProperty("libraryVersion", libraryVersion);
		connection.setRequestProperty("libraryVariant", libraryVariant);
		
		connection.setRequestProperty("ghidraVersion", ghidraVersion);
		connection.setRequestProperty("languageID", languageID.toString());
		connection.setRequestProperty("languageVersion", Integer.toString(languageVersion));
		connection.setRequestProperty("languageMinorVersion", Integer.toString(languageMinorVersion));
		connection.setRequestProperty("compilerSpecID", compilerSpecID.toString());
		connection.setRequestProperty("hashQuad", hashQuad.toString());
		connection.setRequestProperty("funName", funName);
		connection.setRequestProperty("entryPoint", Long.toString(entryPoint));
		connection.setRequestProperty("codeC", tokgroup.toString());
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
			Msg.showError(getClass(), null, "Error", response);
	
		}
		if(connection.getResponseCode() == HttpURLConnection.HTTP_NOT_FOUND) {
			InputStream con = connection.getErrorStream();
			Reader result = new BufferedReader(new InputStreamReader(con, StandardCharsets.UTF_8));
		
			StringBuilder sb = new StringBuilder();
			for (int c; (c = result.read()) >= 0; ) {
				sb.append((char) c);
			}
			response = sb.toString();
			Msg.showError(getClass(), null, "Not connected", response);
		}
}
	
	
 
}
