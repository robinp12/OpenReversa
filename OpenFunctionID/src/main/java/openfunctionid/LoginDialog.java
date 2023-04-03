package openfunctionid;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;

import org.apache.commons.compress.harmony.unpack200.bytecode.forms.ThisFieldRefForm;

import docking.action.DockingAction;

import java.net.URL;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;


public class LoginDialog extends JDialog {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private JTextField tfUsername;
    private JPasswordField pfPassword;
    private JLabel lbUsername;
    private JLabel lbPassword;
    private JButton btnLogin;
    private JButton btnCancel;
    private boolean succeeded;
    
	private static final String USER_AGENT = "Mozilla/5.0";
	private static final String POST_URL = "http://127.0.0.1:5000/";
	
	private static String userId = "";
	private static String message = "Verify credentials";


	public LoginDialog(DockingAction loginAction, DockingAction pullAction, DockingAction deleteAction,
			DockingAction discardAction) {
    	
    	JFrame frame = new JFrame("Please Login Here !");
    	JPanel panel = new JPanel(new GridLayout(3,3));
    	
    	panel.setLayout(new FlowLayout());
    	
	   	frame.setLocationRelativeTo(null);
	   	frame.setSize(650, 100);
	   	frame.setLayout(new FlowLayout());
	   	frame.setVisible(true);	
	   	frame.setResizable(false);
		
		lbUsername = new JLabel("Username: ");
		tfUsername = new JTextField(20);
		lbPassword = new JLabel("Password: ");
		pfPassword = new JPasswordField(20);
		
		btnLogin = new JButton("Login");
		btnCancel = new JButton("Cancel");

		panel.add(lbUsername);		
		panel.add(tfUsername);
		panel.add(lbPassword);
		panel.add(pfPassword);
		panel.add(btnLogin);
		panel.add(btnCancel);

		frame.add(panel, BorderLayout.CENTER);
		
		btnLogin.addActionListener(new ActionListener() {
		    public void actionPerformed(ActionEvent e) {
		    	if (authenticate(getUsername(), getPassword())) {
		    		JOptionPane.showMessageDialog(LoginDialog.this,
		    				"Hi " + getUsername() + "! You are connected.",
		    				"Login",
		    				JOptionPane.INFORMATION_MESSAGE);
		    		succeeded = true;
		    		
		    		loginAction.setEnabled(false);
		            pullAction.setEnabled(true);
		            deleteAction.setEnabled(true);
		            discardAction.setEnabled(true);
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
		    	dispose();
		    }
		});
    }

	public String getUsername() {
        return tfUsername.getText().trim();
    }

    public String getPassword() {
        return new String(pfPassword.getPassword());
    }

    public boolean isSucceeded() {
        return succeeded;
    }
    public static boolean authenticate(String username, String password) {
    	if(username == null || password == null) {
    		return false;
    	}
        try {
			return login_request(username,password);
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}
    }
    private static boolean login_request(String username, String password) throws IOException {
        URL obj = new URL(POST_URL + "login/" + username + "/" + password);
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("User-Agent", USER_AGENT);

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
}