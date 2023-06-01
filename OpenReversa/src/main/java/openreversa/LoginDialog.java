package openreversa;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import docking.action.DockingAction;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * A login dialog class that handles user login and registration.
 */
public class LoginDialog extends JDialog {

    /**
     * Serialization version ID.
     */
    private static final long serialVersionUID = 1L;

    // Login dialog components
    private JTextField nameLogField;
    private JPasswordField passLogField;
    private JLabel nameLogLabel;
    private JLabel passLogLabel;
    private JButton btnLogin;
    private JButton btnCancel;

    // Registration dialog components
    private JTextField nameRegField;
    private JPasswordField passRegField;
    private JPasswordField confirmRegField;
    private JLabel nameRegLabel;
    private JLabel passRegLabel;
    private JLabel confirmRegLabel;
    private JButton btnRegister;
    private JButton confirmRegButt;

    private boolean succeeded;
    private DockingAction loginAction;
    private DockingAction pullAction;
    private DockingAction logoutAction;
    private DockingAction removeAction;
    private DockingAction populateAction;

    // User ID and messages
    public static String userId = "";
    private static String message = "Verify credentials";
    private static String regmessage = "";

    Request request = new Request();

    /**
     * Constructs a LoginDialog instance.
     *
     * @param loginAction    The action associated with login.
     * @param pullAction     The action associated with pulling.
     * @param logoutAction   The action associated with logout.
     * @param removeAction   The action associated with removing.
     * @param populateAction The action associated with populating.
     */
    public LoginDialog(DockingAction loginAction, DockingAction pullAction,
                       DockingAction logoutAction, DockingAction removeAction, DockingAction populateAction) {
        this.loginAction = loginAction;
        this.pullAction = pullAction;
        this.logoutAction = logoutAction;
        this.removeAction = removeAction;
        this.populateAction = populateAction;

        loginDialog();
    }

    /**
     * Gets the entered username in the login dialog.
     *
     * @return The entered username.
     */
    public String getUsername() {
        return nameLogField.getText().trim();
    }

    /**
     * Gets the entered password in the login dialog.
     *
     * @return The entered password.
     */
    public String getPassword() {
        return new String(passLogField.getPassword());
    }

    /**
     * Gets the entered username in the registration dialog.
     *
     * @return The entered username.
     */
    public String getRegisterUsername() {
        return nameRegField.getText().trim();
    }

    /**
     * Gets the entered password in the registration dialog.
     *
     * @return The entered password.
     */
    public String getRegisterPassword() {
        return new String(passRegField.getPassword());
    }

    /**
     * Gets the entered confirmation password in the registration dialog.
     *
     * @return The entered confirmation password.
     */
    public String getConfirm() {
        return new String(confirmRegField.getPassword());
    }

    /**
     * Gets the user ID.
     *
     * @return The user ID.
     */
    public static String getUserId() {
        return userId;
    }

    /**
     * Creates and displays the login dialog.
     */
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

        // Login dialog components initialization
        nameLogLabel = new JLabel("Username: ");
        nameLogField = new JTextField(20);
        passLogLabel = new JLabel("Password: ");
        passLogField = new JPasswordField(20);

        topPanel.add(nameLogLabel);
        topPanel.add(nameLogField);
        topPanel.add(passLogLabel);
        topPanel.add(passLogField);

        btnLogin = new JButton("Login");
        btnCancel = new JButton("Cancel");

        topPanel.add(btnLogin);
        topPanel.add(btnCancel);
        topPanel.setLayout(new GridLayout(3, 2, 5, 2));

        subPanel.setLayout(new GridLayout(1, 3, 5, 2));

        dialog.add(topPanel);
        dialog.add(subPanel);

        JRootPane rootPane = SwingUtilities.getRootPane(btnLogin);
        rootPane.setDefaultButton(btnLogin);

        // Login button action listener
        btnLogin.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                // Check if required fields are filled
                if (nameLogField.getText().isEmpty() || passLogField.getPassword().length == 0) {
                    JOptionPane.showMessageDialog(LoginDialog.this,
                            "Please fill out all required fields to continue.",
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                int isLogged = 0;
                try {
                    isLogged = request.login_request(getUsername(), getPassword());
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
                    populateAction.setEnabled(true);
                    logoutAction.setEnabled(true);
                    removeAction.setEnabled(true);

                    dialog.dispose();
                    dispose();
                } else if (isLogged == 3) {
                    JOptionPane.showMessageDialog(LoginDialog.this,
                            message,
                            "Login error",
                            JOptionPane.ERROR_MESSAGE);
                    passLogField.setText("");
                    succeeded = false;
                } else if (isLogged == 4) {
                    JOptionPane.showMessageDialog(LoginDialog.this,
                            "Sorry, the server is currently unavailable. Please try again later.",
                            "Server error",
                            JOptionPane.ERROR_MESSAGE);
                    passLogField.setText("");
                    succeeded = false;
                } else if (isLogged == 5) {
                    JOptionPane.showMessageDialog(LoginDialog.this,
                            "Sorry, there was an error with the database connection. Please try again later",
                            "database error",
                            JOptionPane.ERROR_MESSAGE);
                    passLogField.setText("");
                    succeeded = false;
                } else {
                    JOptionPane.showMessageDialog(LoginDialog.this,
                            "Verify Your Email Address",
                            "Login error",
                            JOptionPane.ERROR_MESSAGE);
                    passLogField.setText("");
                    succeeded = false;
                }
            }
        });

        // Cancel button action listener
        btnCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                dialog.dispose();
                dispose();
            }
        });

        // Register button action listener
        btnRegister.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                registerDialog();
            }
        });

        dialog.setVisible(true);
    }

    /**
     * Creates and displays the registration dialog.
     */
    private void registerDialog() {
        JDialog dialog = new JDialog();
        dialog.setModal(true);

        JPanel topPanel = new JPanel();
        JPanel subPanel = new JPanel();

        dialog.setLocationRelativeTo(LoginDialog.this);
        dialog.setSize(500, 150);
        dialog.setLayout(new GridLayout(2, 1, 5, 5));
        dialog.setResizable(false);
        dialog.setTitle("Register");

        // Registration dialog components initialization
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
        topPanel.setLayout(new GridLayout(3, 2, 5, 2));

        subPanel.setLayout(new GridLayout(1, 3, 5, 2));

        dialog.add(topPanel);
        dialog.add(subPanel);

        JRootPane rootPane = SwingUtilities.getRootPane(confirmRegButt);
        rootPane.setDefaultButton(confirmRegButt);

        // Sign-in button action listener
        confirmRegButt.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                // Check if required fields are filled and password matches
                if (nameRegField.getText().isEmpty()
                        || passRegField.getPassword().length < 8
                        || confirmRegField.getPassword().length < 8) {
                    JOptionPane.showMessageDialog(LoginDialog.this,
                            "Please fill out all required fields to continue and make sure password is greater or equal to 8.",
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }
                int isRegistered = 0;

                try {
                    if (!getRegisterPassword().equals(getConfirm())) {
                        JOptionPane.showMessageDialog(LoginDialog.this,
                                "The two password fields do not match. Please try again.",
                                "Error",
                                JOptionPane.ERROR_MESSAGE);
                        return;
                    } else {
                        isRegistered = request.register_request(getRegisterUsername(), getRegisterPassword(), getConfirm());
                    }
                } catch (IOException e1) {
                    e1.printStackTrace();
                }

                if (isRegistered == 1) {
                    JOptionPane.showMessageDialog(LoginDialog.this,
                            "A verification email has been sent to your email address.",
                            "Registered",
                            JOptionPane.INFORMATION_MESSAGE);
                    dialog.dispose();
                } else if (isRegistered == 2) {
                    JOptionPane.showMessageDialog(LoginDialog.this,
                            "Sorry, there was an error with the database connection. Please try again later",
                            "Database error",
                            JOptionPane.ERROR_MESSAGE);
                } else if (isRegistered == 3) {
                    JOptionPane.showMessageDialog(LoginDialog.this,
                            regmessage,
                            "Not registered",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        dialog.setVisible(true);
    }
}