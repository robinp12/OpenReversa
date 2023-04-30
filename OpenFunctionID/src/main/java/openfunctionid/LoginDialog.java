package openfunctionid;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

import docking.action.DockingAction;
import ghidra.util.Msg;

import java.net.URL;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;



public class LoginDialog extends JDialog {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private JTextField nameLogField;
	private JTextField nameRegField;

	private JPasswordField passLogField;
	private JPasswordField passRegField;

	private JPasswordField confirmRegField;

    private JLabel nameLogLabel;
    private JLabel nameRegLabel;

    private JLabel passLogLabel;
    private JLabel passRegLabel;
    private JLabel confirmRegLabel;
    private JButton btnLogin;
    private JButton confirmRegButt;

    private JButton btnCancel;
    private JButton btnRegister;

    private boolean succeeded;
	private DockingAction loginAction;
	private DockingAction pullAction;
	private DockingAction deleteAction;
	private DockingAction pushAction;
	private DockingAction logoutAction;
	private DockingAction removeAction;

	private static final String POST_URL = "http://127.0.0.1:5000/";
	
	private static String userId = "";
	private static String message = "Verify credentials";
	private static String regmessage = "";


	public LoginDialog(DockingAction loginAction, DockingAction pullAction, DockingAction pushAction, DockingAction deleteAction,
		 DockingAction logoutAction, DockingAction removeAction) {
		
		this.loginAction = loginAction;
		this.pullAction = pullAction;
		this.deleteAction = deleteAction;
		this.pushAction = pushAction;
		this.logoutAction = logoutAction;
		this.removeAction = removeAction;
		loginDialog();    	
    }

	public String getUsername() {
        return nameLogField.getText().trim();
    }

    public String getPassword() {
        return new String(passLogField.getPassword());
    }
    
    public String getRegisterUsername() {
        return nameRegField.getText().trim();
    }

    public String getRegisterPassword() {
        return new String(passRegField.getPassword());
    }
   
    public String getConfirm() {
        return new String(confirmRegField.getPassword());
    }

    public boolean isSucceeded() {
        return succeeded;
    }
    
    public static String getUserId() {
    	return userId;
    }
    
    public static String hashString(String msg) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(msg.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hash);
    }
    private void loginDialog() {
        JDialog dialog = new JDialog();
        dialog.setModal(true);

        JPanel topPanel = new JPanel();
        JPanel subPanel = new JPanel();

        dialog.setLocationRelativeTo(null);
        dialog.setSize(500, 150);
        dialog.setLayout(new GridLayout(2, 1, 5, 5));
        dialog.setResizable(false);

        dialog.setTitle("Login");

        nameLogLabel = new JLabel("Username: ");
        nameLogField = new JTextField(20);
        passLogLabel = new JLabel("Password: ");
        passLogField = new JPasswordField(20);

        topPanel.add(nameLogLabel);
        topPanel.add(nameLogField);
        topPanel.add(passLogLabel);
        topPanel.add(passLogField);

        btnLogin = new JButton("Login");
        btnRegister = new JButton("Register");
        subPanel.add(new JLabel());
        subPanel.add(btnRegister);
        subPanel.add(new JLabel());

        btnCancel = new JButton("Cancel");

        topPanel.add(btnLogin);
        topPanel.add(btnCancel);
        topPanel.setLayout(new GridLayout(3, 2, 5, 2));

        subPanel.setLayout(new GridLayout(1, 3, 5, 2));

        dialog.add(topPanel);
        dialog.add(subPanel);

        JRootPane rootPane = SwingUtilities.getRootPane(btnLogin);
        rootPane.setDefaultButton(btnLogin);

        btnLogin.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                if (nameLogField.getText().isEmpty()
                        || passLogField.getPassword().length == 0) {
                    JOptionPane.showMessageDialog(LoginDialog.this,
                            "Please fill out all required fields to continue.",
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }
                int isLogged = 0;
                try {
                    isLogged = login_request(getUsername(), getPassword());
                } catch (IOException e1) {
                    e1.printStackTrace();
                }

                if (isLogged == 1) {
                	JOptionPane.showMessageDialog(rootPane,
                		    "Welcome !",
                		    "Logged in",
                		    JOptionPane.INFORMATION_MESSAGE);
                		succeeded = true;

                    loginAction.setEnabled(false);
                    pullAction.setEnabled(true);
                    deleteAction.setEnabled(true);
                    pushAction.setEnabled(true);
                    logoutAction.setEnabled(true);
                    removeAction.setEnabled(true);
                    OpenFunctionIDUploadC.setConnected(true); 

                    dialog.dispose();
                    dispose();
                } else if (isLogged == 3) {
                    JOptionPane.showMessageDialog(LoginDialog.this,
                            message,
                            "Login error",
                            JOptionPane.ERROR_MESSAGE);
                    // reset password
                    passLogField.setText("");
                    succeeded = false;
                } else {
                	JOptionPane.showMessageDialog(LoginDialog.this,
                            "Verify Your Email Address",
                            "Login error",
                            JOptionPane.ERROR_MESSAGE);
                    // reset password
                    passLogField.setText("");
                    succeeded = false;
                }
                
                
            }
        });

        btnCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                dialog.dispose();
                dispose();
            }
        });

        btnRegister.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                registerDialog();
            }
        });

        dialog.setVisible(true);
    }
    
    private void registerDialog() {
    	
    	JDialog dialog = new JDialog();
        dialog.setModal(true);
        
    	JPanel topPanel = new JPanel();
    	JPanel subPanel = new JPanel();
    	
	   	dialog.setLocationRelativeTo(LoginDialog.this);
	   	dialog.setSize(500, 150);
	   	dialog.setLayout(new GridLayout(2,1,5,5));
	   	dialog.setResizable(false);
   		dialog.setTitle("Register");
   				
		nameRegLabel = new JLabel("Username: ");
		nameRegField = new JTextField(20);
		passRegLabel = new JLabel("Password: ");
		passRegField = new JPasswordField(20);

		topPanel.add(nameRegLabel);
		topPanel.add(nameRegField);
		topPanel.add(passRegLabel);
		topPanel.add(passRegField);
				
		confirmRegLabel = new JLabel("Confirm Password: ");
		confirmRegField = new JPasswordField(20);
		
		topPanel.add(confirmRegLabel);
		topPanel.add(confirmRegField);

		confirmRegButt = new JButton("Sign-in");
		
		subPanel.add(confirmRegButt);
		topPanel.setLayout(new GridLayout(3,2,5,2));
		
		subPanel.setLayout(new GridLayout(1,3,5,2));
						
		dialog.add(topPanel);
		dialog.add(subPanel);
		
		JRootPane rootPane = SwingUtilities.getRootPane(confirmRegButt); 
		rootPane.setDefaultButton(confirmRegButt);

		confirmRegButt.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
		    	if(nameRegField.getText().isEmpty()
		    			|| passRegField.getPassword().length <= 4
		    			||  confirmRegField.getPassword().length <= 4) {
		    		JOptionPane.showMessageDialog(LoginDialog.this,
		    				"Please fill out all required fields to continue and make sure password is greater than 4.",
	    					"Error",
	    					JOptionPane.ERROR_MESSAGE);
		    		return;
		    	}
		    	boolean isRegistered = false;
	    		
				try {
					if(!getRegisterPassword().equals(getConfirm())) {						
						JOptionPane.showMessageDialog(LoginDialog.this,
								"The two password fields do not match. Please try again.",
		    					"Error",
		    					JOptionPane.ERROR_MESSAGE);
						return;
					}
					else {
						isRegistered = register_request(getRegisterUsername(), getRegisterPassword(), getConfirm());
					}
				} catch (IOException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				
		    	if (isRegistered) {
	    			JOptionPane.showMessageDialog(LoginDialog.this,
	    					regmessage,
	    					"Registred",
	    					JOptionPane.INFORMATION_MESSAGE);
	    			dialog.dispose();

	    		}
	    		if(!isRegistered) {
	    			JOptionPane.showMessageDialog(LoginDialog.this,
	    					regmessage,
	    					"Not registred",
	    					JOptionPane.ERROR_MESSAGE);
	    		}
		    }
		});  
		dialog.setVisible(true);
    }
    
    private int login_request(String username, String password) throws IOException {
        URL obj = new URL(POST_URL + "get_salt");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        String payload;
        try {
            payload = String.format("{\"username\":\"%s\"}", username);
            con.setDoOutput(true);
            try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                byte[] postData = payload.getBytes(StandardCharsets.UTF_8);
                wr.write(postData);
            }
        } catch (Exception e) {
            // TODO Auto-generated catch block
            message = "Sorry, the server is currently unavailable. Please try again later.";
            e.printStackTrace();
        }
        int responseCode = con.getResponseCode();
        System.out.println("POST Response Code :: " + responseCode);
        if (responseCode == HttpURLConnection.HTTP_OK) { // success
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            
            if(response.toString().contains("didnt verify")) {
            	return 2;
            }
            
	        String[] saltAndPwdHash = response.toString().split(",");
	    	boolean decrypt = Encryption.verifyUserPassword(password, saltAndPwdHash[1], saltAndPwdHash[0]);
	    	if (decrypt) {
	    		userId = saltAndPwdHash[2];
	    		return 1;
	    	}return 3;
        	
        } else {
            System.out.println("GET request did not work.");
            return 3;
        }
    }	
 
   
    private static boolean isValidEmailAddress(String email) {
        String regex = "^[\\w!#$%&'*+/=?`{|}~^-]+(?:\\.[\\w!#$%&'*+/=?`{|}~^-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }

    private static boolean register_request(String username, String password, String confirm) throws IOException {
        if (!isValidEmailAddress(username)) {
            // Show an error message to the user
            regmessage = "Invalid email address.";
            return false;
        }
    	
    	String saltvalue = Encryption.getSaltvalue(30);
    	String encryptedpassword = Encryption.generateSecurePassword(password, saltvalue);
    	URL obj = new URL(POST_URL + "register");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        String payload;
		try {
			payload = String.format("{\"username\":\"%s\",\"pwdHash\":\"%s\",\"salt\":\"%s\"}", username, encryptedpassword, saltvalue);
			//payload = String.format("{\"username\":\"%s\",\"pwdHash\":\"%s\"}", username, hashString(password));
			con.setDoOutput(true);
	        try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
	            byte[] postData = payload.getBytes(StandardCharsets.UTF_8);
	            wr.write(postData);
	        }
		} catch (Exception e) {
			// TODO Auto-generated catch block
	        regmessage = "Sorry, the server is currently unavailable. Please try again later.";
			e.printStackTrace();
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
            
            regmessage = response.toString();
            System.out.println(regmessage);
            
            if(response.toString().contains("Success!")) {
            	return true;
            }
            if(response.toString().contains("Sorry")) {
            	return false;
            }
        }
        else {
        	System.out.println("POST request did not work.");
        	return false;
        }
		return false;
    }
}