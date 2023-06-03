package openreversa;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.DefaultListModel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import com.google.gson.Gson;

import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.LanguageID;
import ghidra.util.Msg;

/**
 * @author Robin Paquet and Arnaud Delcorte
 * 
 * This class is used to make request to the server
 */
public class Request {

    private static final String POST_URL = "https://enigmatic-bayou-51531.herokuapp.com/";
    public static String regmessage = "";

    /**
     * Checks if the given email address is valid.
     *
     * @param email the email address to check
     * @return true if the email address is valid, false otherwise
     */
    private static boolean isValidEmailAddress(String email) {
        String regex = "^[\\w!#$%&'*+/=?`{|}~^-]+(?:\\.[\\w!#$%&'*+/=?`{|}~^-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }

    /**
     * Sends a login request to the server.
     *
     * @param username the username to log in
     * @param password the password for the user
     * @return the login status code: 1 for success, 2 for incorrect credentials, 3 for decryption failure,
     * 4 for server error, 5 for invalid response code
     * @throws IOException if an I/O error occurs while sending the request
     */
    public int login_request(String username, String password) throws IOException {
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
            String message = "Sorry, the server is currently unavailable. Please try again later.";
            e.printStackTrace();
        }
        int responseCode = 0;
        try {
            responseCode = con.getResponseCode();
            System.out.println("POST Response Code :: " + responseCode);
        } catch (Exception e) {
            return 4;
        }
        if (responseCode == HttpURLConnection.HTTP_OK) { // success
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            if (response.toString().contains("didnt verify")) {
                return 2;
            }

            String[] userAndPwdHash = response.toString().split(",");
            boolean decrypt = Encryption.verifyUserPassword(password,userAndPwdHash[0]);
            if (decrypt) {
                LoginDialog.userId = userAndPwdHash[1];
                return 1;
            }
            return 3;
        } else if (responseCode == 500) {
            System.out.println("POST request did not work.");
            return 5;

        } else {
            System.out.println("GET request did not work.");
            return 4;
        }
    }

    /**
     * Sends a registration request to the server.
     *
     * @param username the username to register
     * @param password the password for the user
     * @param confirm  the password confirmation
     * @return the registration status code: 1 for success, 2 for server error, 3 for invalid email address, 4 for other errors
     * @throws IOException if an I/O error occurs while sending the request
     */
    public int register_request(String username, String password, String confirm) throws IOException {
        if (!isValidEmailAddress(username)) {
            // Show an error message to the user
            regmessage = "Invalid email address.";
            return 3;
        }

        String encryptedpassword = Encryption.generateSecurePassword(password);
        URL obj = new URL(POST_URL + "register");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        String payload;
        try {
            payload = String.format("{\"username\":\"%s\",\"pwdHash\":\"%s\"}", username,
                    encryptedpassword);
            con.setDoOutput(true);
            try (DataOutputStream wr = new DataOutputStream(con.getOutputStream())) {
                byte[] postData = payload.getBytes(StandardCharsets.UTF_8);
                wr.write(postData);
            }
        } catch (Exception e) {
            regmessage = "Sorry, the server is currently unavailable. Please try again later.";
            e.printStackTrace();
        }
        int responseCode = con.getResponseCode();
        try {
            responseCode = con.getResponseCode();
            System.out.println("POST Response Code :: " + responseCode);
        } catch (Exception e) {
            return 4;
        }
        System.out.println("POST Response Code :: " + responseCode);

        if (responseCode == HttpURLConnection.HTTP_OK) { // success
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();

            regmessage = response.toString();

            if (response.toString().contains("Success!")) {
                return 1;
            }

            if (response.toString().contains("Sorry")) {
                return 3;
            }
        } else if (responseCode == 500) {
            System.out.println("POST request did not work.");
            return 2;

        } else {
            System.out.println("POST request did not work.");
            return 3;
        }
        return 3;
    }

    /**
     * Retrieves a list of functions from the server.
     *
     * @return a list of lists containing the files and their details, or null if an error occurs
     * @throws Exception if an error occurs while retrieving the files
     */
    public List<List<String>> pullRequest() throws Exception {
        URL url = new URL(POST_URL + "download_files");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
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

            return result;

        } else if (responseCode == 500) {
            JOptionPane.showMessageDialog(null,
                    "Sorry, there was an error with the database connection. Please try again later", "Database error",
                    JOptionPane.ERROR_MESSAGE);
            return null;
        } else {
            JOptionPane.showMessageDialog(null, "Sorry, the server is currently unavailable. Please try again later.",
                    "Server error", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    /**
     * Retrieve the functions the user has pushed in the database in order to delete them next.
     *
     * @param user the user for whom to retrieve the functions
     * @throws Exception if an error occurs while making the request
     */
    public void removeRequest(String user) throws Exception {
        // Construct the URL for the remove request
        URL url = new URL(POST_URL + "get_remove/" + user);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        if (responseCode == HttpURLConnection.HTTP_OK) {
            System.out.println("Response code: " + responseCode);

            BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            String inputLine;
            StringBuffer response = new StringBuffer();

            // Read the response from the server
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();


            // Parse the response as JSON using Gson
            Gson gson = new Gson();
            Object[] items = gson.fromJson(response.toString(), Object[].class);

            // Decode the items from Base64 encoding
            for (int i = 0; i < items.length; i++) {
                items[i] = new String(Base64.getDecoder().decode((String) items[i]), StandardCharsets.UTF_8);
            }

            // Create a JList to display the items
            DefaultListModel<Object> listModel = new DefaultListModel<>();
            listModel.addAll(Arrays.asList(items));
            JList<Object> jList = new JList<>(listModel);

            // Add a selection listener to the JList
            jList.addListSelectionListener(new ListSelectionListener() {
                @Override
                public void valueChanged(ListSelectionEvent e) {
                    if (!e.getValueIsAdjusting()) {
                        Object selectedItem = jList.getSelectedValue();
                        // Handle the selected item
                    }
                }
            });

            // Show a dialog with the JList for item selection
            int result = JOptionPane.showConfirmDialog(null, jList, "Select function to remove",
                    JOptionPane.OK_CANCEL_OPTION);
            if (result == JOptionPane.OK_OPTION) {
                Object selectedItem = jList.getSelectedValue();
                // Ask for confirmation before deleting the selected item
                int choice = JOptionPane.showConfirmDialog(null, "Are you sure you want to delete this function ?",
                        "Confirmation", JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
                if (choice == JOptionPane.YES_OPTION) {
                    if (selectedItem != null) {
                        // Delete the selected item
                        deleteSelectedItem(Base64.getEncoder().encodeToString(selectedItem.toString().getBytes(StandardCharsets.UTF_8)));
                    } else {
                        Msg.showError(getClass(), null, "Error", "No function selected.");
                    }
                }
            }
        } else if (responseCode == 500) {
            JOptionPane.showMessageDialog(null,
                    "Sorry, there was an error with the database connection. Please try again later", "Database error",
                    JOptionPane.ERROR_MESSAGE);
        } else {
            JOptionPane.showMessageDialog(null, "Sorry, the server is currently unavailable. Please try again later.",
                    "Server error", JOptionPane.ERROR_MESSAGE);
        }
    }


    /**
     * Deletes the selected item from the database with a request to the server.
     *
     * @param item the item to delete
     * @return true if the item is deleted successfully, false otherwise
     * @throws Exception if an error occurs while deleting the item
     */
    public boolean deleteSelectedItem(String item) throws Exception {
        URL obj = new URL(POST_URL + "delete_selected");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);

        // Get the user ID from the login dialog
        String userfrom = LoginDialog.getUserId();

        // Create the payload with the item to delete
        String payload = String.format("{\"item\":\"%s\"}", item);

        // Send the payload to the server
        OutputStream os = con.getOutputStream();
        os.write(payload.getBytes());
        os.flush();
        os.close();

        // Get the response code from the server
        int responseCode = con.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();

            // Read the response from the server
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            String regmessage = response.toString();

            if (response.toString().contains("Success!")) {
                JOptionPane.showMessageDialog(null, regmessage);
                return true;
            }
        } else if (responseCode == 500) {
            JOptionPane.showMessageDialog(null, "Sorry, there was an error with the database connection. Please try again later", "Database error", JOptionPane.ERROR_MESSAGE);
            return false;
        }

        return true;
    }

    /**
     * Reports an item to the server.
     *
     * @param item the item to report
     * @return true if the item is reported successfully, false otherwise
     * @throws IOException if an error occurs while reporting the item
     */
    public boolean report(MyItem item) throws IOException {
        URL obj = new URL(POST_URL + "report");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);

        // Get the user ID from the login dialog
        String userfrom = LoginDialog.getUserId();

        // Create the payload with the item details
        String payload = String.format("{\"userto\":\"%s\",\"userfrom\":\"%s\",\"funname\":\"%s\"}", item.getUser(), userfrom, item.getFun_name());

        // Send the payload to the server
        OutputStream os = con.getOutputStream();
        os.write(payload.getBytes());
        os.flush();
        os.close();

        // Get the response code from the server
        int responseCode = con.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();

            // Read the response from the server
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            regmessage = response.toString();

            if (response.toString().contains("Success!")) {
                return true;
            }
        } else if (responseCode == 500) {
            JOptionPane.showMessageDialog(null, "Sorry, there was an error with the database connection. Please try again later", "Database error", JOptionPane.ERROR_MESSAGE);
            return false;
        } else {
            System.out.println("POST request did not work.");
        }

        return true;
    }

    /**
     * Sends a discussion message about an item to the server.
     *
     * @param item    the item to discuss
     * @param message the message to send
     * @return true if the message is sent successfully, false otherwise
     * @throws IOException if an error occurs while sending the message
     */
    public boolean discuss(MyItem item, String message) throws IOException {
        URL obj = new URL(POST_URL + "discuss");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);

        // Create the payload with the item details and message
        String userfrom = LoginDialog.getUserId();
        String payload = String.format("{\"userto\":\"%s\",\"userfrom\":\"%s\",\"funname\":\"%s\",\"message\":\"%s\"}", item.getUser(), userfrom, item.getFun_name(), message);

        // Send the payload to the server
        OutputStream os = con.getOutputStream();
        os.write(payload.getBytes());
        os.flush();
        os.close();

        // Get the response code from the server
        int responseCode = con.getResponseCode();

        if (responseCode == HttpURLConnection.HTTP_OK) {
            BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
            String inputLine;
            StringBuilder response = new StringBuilder();

            // Read the response from the server
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
            in.close();
            regmessage = response.toString();

            if (response.toString().contains("Success!")) {
                JOptionPane.showMessageDialog(null, regmessage);
                return true;
            }
        } else if (responseCode == 500) {
            JOptionPane.showMessageDialog(null, "Sorry, there was an error with the database connection. Please try again later", "Database error", JOptionPane.ERROR_MESSAGE);
            return false;
        } else {
            System.out.println("POST request did not work.");
        }

        return true;
    }

    /**
     * Sends a request to the server to store function information in the database.
     *
     * @param codeUnitSize               the size of the code unit
     * @param fullHash                   the full hash value
     * @param specificHashAdditionalSize the additional size of the specific hash
     * @param specificHash               the specific hash value
     * @param libraryFamilyName          the library family name
     * @param libraryVersion             the library version
     * @param libraryVariant             the library variant
     * @param ghidraVersion              the Ghidra version
     * @param languageID                 the language ID
     * @param languageVersion            the language version
     * @param languageMinorVersion       the language minor version
     * @param compilerSpecID             the compiler spec ID
     * @param funName                    the function name
     * @param entryPoint                 the entry point
     * @param signature                  the function signature
     * @param tokgroup                   the token group
     * @param comment                    the comment
     * @return true if the request is sent successfully, false otherwise
     * @throws IOException if an error occurs while sending the request
     */
    public boolean sendToDBrequest(short codeUnitSize, long fullHash, byte specificHashAdditionalSize,
                                   long specificHash, String libraryFamilyName, String libraryVersion, String libraryVariant,
                                   String ghidraVersion, LanguageID languageID, int languageVersion, int languageMinorVersion,
                                   CompilerSpecID compilerSpecID, String funName, long entryPoint, String signature,
                                   String tokgroup, String comment) throws IOException {

        URL url = new URL(POST_URL + "fid");
        String response = "";

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/json");
        String payload;

        try {
            // Create the payload with all the necessary function information
            payload = String.format("{\"unique_id\":\"%s\",\"confirm\":\"%s\",\"codeUnitSize\":\"%s\",\"fullHash\":\"%s\",\"specificHashAdditionalSize\":\"%s\",\"specificHash\":\"%s\",\"libraryFamilyName\":\"%s\",\"libraryVersion\":\"%s\",\"libraryVariant\":\"%s\",\"ghidraVersion\":\"%s\",\"languageID\":\"%s\",\"languageVersion\":\"%s\",\"languageMinorVersion\":\"%s\",\"compilerSpecID\":\"%s\",\"funName\":\"%s\",\"signature\":\"%s\",\"entryPoint\":\"%s\",\"codeC\":\"%s\",\"comment\":\"%s\"}",
                    LoginDialog.getUserId(), "0", Short.toString(codeUnitSize), Long.toString(fullHash),
                    Byte.toString(specificHashAdditionalSize), Long.toString(specificHash), libraryFamilyName,
                    libraryVersion, libraryVariant, ghidraVersion, languageID.toString(), Integer.toString(languageVersion),
                    Integer.toString(languageMinorVersion), compilerSpecID.toString(), funName, signature,
                    Long.toString(entryPoint), Base64.getEncoder().encodeToString(tokgroup.getBytes(StandardCharsets.UTF_8)),
                    comment);

            connection.setDoOutput(true);
            try (DataOutputStream wr = new DataOutputStream(connection.getOutputStream())) {
                byte[] postData = payload.getBytes(StandardCharsets.UTF_8);
                wr.write(postData);
            }
        } catch (Exception e) {
            regmessage = "Sorry, the server is currently unavailable. Please try again later.";
            e.printStackTrace();
        }

        if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
            InputStream con = connection.getInputStream();
            Reader result = new BufferedReader(new InputStreamReader(con, StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();

            // Read the response from the server
            for (int c; (c = result.read()) >= 0; ) {
                sb.append((char) c);
            }

            response = sb.toString();
            Msg.showInfo(getClass(), null, "Function uploaded", response);
            return true;
        } else if (connection.getResponseCode() == 500) {
            JOptionPane.showMessageDialog(null, "Sorry, there was an error with the database connection. Please try again later", "Database error", JOptionPane.ERROR_MESSAGE);
            return false;
        } else if (connection.getResponseCode() == HttpURLConnection.HTTP_CONFLICT) {
            InputStream con = connection.getErrorStream();
            Reader result = new BufferedReader(new InputStreamReader(con, StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();

            // Read the error message from the server
            for (int c; (c = result.read()) >= 0; ) {
                sb.append((char) c);
            }

            connection.disconnect();

            // Ask the user if they want to add the function anyway
            int res = JOptionPane.showConfirmDialog(null, sb.toString() + " Do you want to add it anyway?", "Confirm", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

            if (res == JOptionPane.YES_OPTION) {
                URL url1 = new URL(POST_URL + "fid");

                HttpURLConnection connection1 = (HttpURLConnection) url1.openConnection();
                String payload1;

                try {
                    // Create the payload to add the function despite the conflict
                    payload1 = String.format("{\"unique_id\":\"%s\",\"confirm\":\"%s\",\"codeUnitSize\":\"%s\",\"fullHash\":\"%s\",\"specificHashAdditionalSize\":\"%s\",\"specificHash\":\"%s\",\"libraryFamilyName\":\"%s\",\"libraryVersion\":\"%s\",\"libraryVariant\":\"%s\",\"ghidraVersion\":\"%s\",\"languageID\":\"%s\",\"languageVersion\":\"%s\",\"languageMinorVersion\":\"%s\",\"compilerSpecID\":\"%s\",\"funName\":\"%s\",\"signature\":\"%s\",\"entryPoint\":\"%s\",\"codeC\":\"%s\",\"comment\":\"%s\"}",
                            LoginDialog.getUserId(), "1", Short.toString(codeUnitSize), Long.toString(fullHash),
                            Byte.toString(specificHashAdditionalSize), Long.toString(specificHash), libraryFamilyName,
                            libraryVersion, libraryVariant, ghidraVersion, languageID.toString(), Integer.toString(languageVersion),
                            Integer.toString(languageMinorVersion), compilerSpecID.toString(), funName, signature,
                            Long.toString(entryPoint), Base64.getEncoder().encodeToString(tokgroup.getBytes(StandardCharsets.UTF_8)),
                            comment);

                    connection1.setRequestMethod("POST");
                    connection1.setRequestProperty("Content-Type", "application/json");
                    connection1.setDoOutput(true);
                    try (DataOutputStream wr = new DataOutputStream(connection1.getOutputStream())) {
                        byte[] postData = payload1.getBytes(StandardCharsets.UTF_8);
                        wr.write(postData);
                    }
                } catch (Exception e) {
                    regmessage = "Sorry, the server is currently unavailable. Please try again later.";
                    e.printStackTrace();
                }

                if (connection1.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    InputStream con1 = connection1.getInputStream();
                    Reader result1 = new BufferedReader(new InputStreamReader(con1, StandardCharsets.UTF_8));

                    StringBuilder sb1 = new StringBuilder();

                    // Read the response from the server
                    for (int c; (c = result1.read()) >= 0; ) {
                        sb1.append((char) c);
                    }

                    response = sb1.toString();
                    Msg.showInfo(getClass(), null, "Function uploaded", response);
                    return true;
                }
            }
        } else {
            JOptionPane.showMessageDialog(null, "Sorry, there was an error with the server. Please try again later", "Server error", JOptionPane.ERROR_MESSAGE);
        }

        return false;
    }

}
