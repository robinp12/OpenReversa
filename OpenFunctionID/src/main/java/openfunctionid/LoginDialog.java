package openfunctionid;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

import docking.action.DockingAction;

import java.net.URL;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;



public class LoginDialog extends JDialog {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private JTextField tfUsername;
	private JTextField regtfUsername;

	private JPasswordField pfPassword;
	private JPasswordField regpfPassword;

	private JPasswordField regpfConfirm;

    private JLabel lbUsername;
    private JLabel reglbUsername;

    private JLabel lbPassword;
    private JLabel reglbPassword;
    private JLabel reglbConfirm;
    private JButton btnLogin;
    private JButton regbtnSignin;

    private JButton btnCancel;
    private JButton btnRegister;

    private boolean succeeded;
	private DockingAction loginAction;
	private DockingAction pullAction;
	private DockingAction deleteAction;
	private DockingAction discardAction;

	
	private static final String USER_AGENT = "Mozilla/5.0";
	private static final String POST_URL = "http://127.0.0.1:5000/";
	
	private static String userId = "";
	private static String message = "Verify credentials";
	private static String regmessage = "Verify credentials";


	public LoginDialog(DockingAction loginAction, DockingAction pullAction, DockingAction deleteAction,
			DockingAction discardAction) {
		
		this.loginAction = loginAction;
		this.pullAction = pullAction;
		this.deleteAction = deleteAction;
		this.discardAction = discardAction;
		
		loginDialog();    	
    }

	public String getUsername() {
        return tfUsername.getText().trim();
    }

    public String getPassword() {
        return new String(pfPassword.getPassword());
    }
    
    public String getRegisterUsername() {
        return regtfUsername.getText().trim();
    }

    public String getRegisterPassword() {
        return new String(regpfPassword.getPassword());
    }
   
    public String getConfirm() {
        return new String(regpfConfirm.getPassword());
    }

    public boolean isSucceeded() {
        return succeeded;
    }
    
    public static String hashString(String message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(message.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(hash);
    }
    private void loginDialog() {
    	
    	JFrame frame = new JFrame();
    	JPanel panel = new JPanel();
    	JPanel panel1 = new JPanel();
    	
	   	frame.setLocationRelativeTo(null);
	   	frame.setSize(500, 150);
	   	frame.setLayout(new GridLayout(2,1,5,5));
	   	frame.setVisible(true);	
	   	frame.setResizable(false);
	   	
   		frame.setTitle("Please Login Here !");
		
		lbUsername = new JLabel("Username: ");
		tfUsername = new JTextField(20);
		lbPassword = new JLabel("Password: ");
		pfPassword = new JPasswordField(20);

		panel.add(lbUsername);		
		panel.add(tfUsername);
		panel.add(lbPassword);
		panel.add(pfPassword);
		
		btnLogin = new JButton("Login");
		btnRegister = new JButton("Register");
		panel1.add(new JLabel());
		panel1.add(btnRegister);
		panel1.add(new JLabel());
	
		btnCancel = new JButton("Cancel");		
	
		panel.add(btnLogin);
		panel.add(btnCancel);
		panel.setLayout(new GridLayout(3,2,5,2));
		
		panel1.setLayout(new GridLayout(1,3,5,2));
						
		frame.add(panel);
		frame.add(panel1);

		btnLogin.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
		    	if(tfUsername.getText().isEmpty() 
		    			|| pfPassword.getPassword().length == 0) {
		    		JOptionPane.showMessageDialog(LoginDialog.this,
		    				"Please fill in the form.",
	    					"Form not complet !",
	    					JOptionPane.INFORMATION_MESSAGE);
		    		return;
		    	}
		    	boolean isLogged = false;
				try {
					isLogged = login_request(getUsername(), getPassword());
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
				
	    		if (isLogged) {
	    			JOptionPane.showMessageDialog(LoginDialog.this,
	    					"Hi " + getUsername() + "! You are connected.",
	    					"Login",
	    					JOptionPane.INFORMATION_MESSAGE);
	    			succeeded = true;
	    			
	    			loginAction.setEnabled(false);
	    			pullAction.setEnabled(true);
	    			deleteAction.setEnabled(true);
	    			discardAction.setEnabled(true);
	    			frame.dispose();
	    			dispose();
	    		} 
	    		else {
	    			JOptionPane.showMessageDialog(LoginDialog.this, 
	    					message, 
	    					"Login",
	    					JOptionPane.ERROR_MESSAGE);
	    			// reset password
	    			pfPassword.setText("");
	    			succeeded = false;
	    		}		    	
		    }
		});
		
		btnCancel.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
	    		frame.dispose();
		    	dispose();
		    }
		});
		
		btnRegister.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
	    		registerDialog();
		    }
		});
    	
    }
    
    private void registerDialog() {
    	
    	JFrame frame = new JFrame();
    	JPanel panel = new JPanel();
    	JPanel panel1 = new JPanel();
    	
	   	frame.setLocationRelativeTo(null);
	   	frame.setSize(500, 150);
	   	frame.setLayout(new GridLayout(2,1,5,5));
	   	frame.setVisible(true);	
	   	frame.setResizable(false);
   		frame.setTitle("Please Sign-in Here !");
   				
		reglbUsername = new JLabel("Username: ");
		regtfUsername = new JTextField(20);
		reglbPassword = new JLabel("Password: ");
		regpfPassword = new JPasswordField(20);

		panel.add(reglbUsername);		
		panel.add(regtfUsername);
		panel.add(reglbPassword);
		panel.add(regpfPassword);
				
		reglbConfirm = new JLabel("Confirm Password: ");
		regpfConfirm = new JPasswordField(20);
		
		panel.add(reglbConfirm);
		panel.add(regpfConfirm);
		
		regbtnSignin = new JButton("Sign-in");
		
		panel1.add(regbtnSignin);
		panel.setLayout(new GridLayout(3,2,5,2));
		
		panel1.setLayout(new GridLayout(1,3,5,2));
						
		frame.add(panel);
		frame.add(panel1);

		regbtnSignin.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
		    	if(regtfUsername.getText().isEmpty() 
		    			|| regpfPassword.getPassword().length == 0 
		    			||  regpfConfirm.getPassword().length == 0) {
		    		JOptionPane.showMessageDialog(LoginDialog.this,
	    					"Please fill in the form.",
	    					"Form not complet !",
	    					JOptionPane.INFORMATION_MESSAGE);
		    		return;
		    	}
		    	boolean isRegistered = false;
	    		
		    	try {
					isRegistered = register_request(getRegisterUsername(), getRegisterPassword(), getConfirm());
				} catch (Exception e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
		    	
		    	if (isRegistered) {
	    			JOptionPane.showMessageDialog(LoginDialog.this,
	    					"Hi " + getUsername() + "! You are signed in.",
	    					"Registred",
	    					JOptionPane.INFORMATION_MESSAGE);
	    			frame.dispose();

	    		}
	    		else {
	    			JOptionPane.showMessageDialog(LoginDialog.this,
	    					regmessage,
	    					"Not registred",
	    					JOptionPane.ERROR_MESSAGE);
	    		}
		    }
		});    	
    }
        
    private static boolean login_request(String username, String password) throws Exception {
    	
    	URL obj = new URL(POST_URL + "login");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        String payload = String.format("{\"username\":\"%s\",\"pwdHash\":\"%s\"}", username,hashString(password));

        con.setDoOutput(true);
        try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
            byte[] postData = payload.getBytes(StandardCharsets.UTF_8);
            wr.write(postData);
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
            
            message = response.toString();
            System.out.println(response.toString());
            
            if(response.toString().contains("Logged in :")) {
            	String[] sentences = response.toString().split(": ");  
            	userId = sentences[1];
            	return true;
            }
        } 
        else {
        	System.out.println("POST request did not work.");
        	return false;
        }
		return false;
    }
    private static boolean register_request(String username, String password, String confirm) throws Exception {
    	
    	URL obj = new URL(POST_URL + "register");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        String payload = String.format("{\"username\":\"%s\",\"pwdHash\":\"%s\"}", username,hashString(password));

        con.setDoOutput(true);
        try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
            byte[] postData = payload.getBytes(StandardCharsets.UTF_8);
            wr.write(postData);
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
            System.out.println(response.toString());
            
            if(response.toString().contains("Registered to DB")) {
            	return true;
            }
            if(response.toString().contains("User already exists")) {
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