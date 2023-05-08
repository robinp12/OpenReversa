package openfunctionid;

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

public class Request {

    private static final String POST_URL = "http://127.0.0.1:5000/";
    private static String regmessage = "";

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
            // TODO Auto-generated catch block
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

            String[] saltAndPwdHash = response.toString().split(",");
            boolean decrypt = Encryption.verifyUserPassword(password, saltAndPwdHash[1], saltAndPwdHash[0]);
            if (decrypt) {
                LoginDialog.userId = saltAndPwdHash[2];
                return 1;
            }
            return 3;

        } else {
            System.out.println("GET request did not work.");
            return 4;
        }
    }

    public static boolean register_request(String username, String password, String confirm) throws IOException {
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
        try {
            responseCode = con.getResponseCode();
            System.out.println("POST Response Code :: " + responseCode);
        } catch (Exception e) {
            return false;
        }
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

            if (response.toString().contains("Success!")) {
                return true;
            }
            if (response.toString().contains("Sorry")) {
                return false;
            }
        } else {
            System.out.println("POST request did not work.");
            return false;
        }
        return false;
    }

    private static boolean isValidEmailAddress(String email) {
        String regex = "^[\\w!#$%&'*+/=?`{|}~^-]+(?:\\.[\\w!#$%&'*+/=?`{|}~^-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }

    public List<List<String>> pullRequest() throws Exception {
        URL url = new URL(POST_URL + "download_files");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
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

    }

    public boolean removeRequest(String user) throws Exception {
        URL url = new URL(POST_URL + "get_remove/" + user);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        System.out.println("Response code: " + responseCode);

        BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
        String inputLine;
        StringBuffer response = new StringBuffer();

        while ((inputLine = in.readLine()) != null) {
            response.append(inputLine);
        }
        in.close();

        System.out.println(response.toString());

        Gson gson = new Gson();
        Object[] items = gson.fromJson(response.toString(), Object[].class);

        DefaultListModel<Object> listModel = new DefaultListModel<>();
        listModel.addAll(Arrays.asList(items));
        JList<Object> jList = new JList<>(listModel);

        jList.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                if (!e.getValueIsAdjusting()) {
                    Object selectedItem = jList.getSelectedValue();
                }
            }
        });

        int result = JOptionPane.showConfirmDialog(null, jList, "Select function to remove", JOptionPane.OK_CANCEL_OPTION);
        if (result == JOptionPane.OK_OPTION) {
            Object selectedItem = jList.getSelectedValue();
            deleteSelectedItem(selectedItem.toString());
        }

        return true;
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

            if (response.toString().contains("Success!")) {
                JOptionPane.showMessageDialog(null, regmessage);
                return true;
            } else {
                return false;
            }

        } else {
            System.out.println("POST request did not work.");
            return false;
        }
    }

    public boolean report(MyItem item) throws IOException {
        URL obj = new URL(POST_URL + "report");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);
        String userfrom = LoginDialog.getUserId();
        String payload = String.format("{\"userto\":\"%s\",\"userfrom\":\"%s\",\"funname\":\"%s\"}", item.getUser(), userfrom, item.getFun_name());

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

            if (response.toString().contains("Success!")) {
                return true;
            } else {
                return false;
            }

        } else {
            System.out.println("POST request did not work.");
            return false;
        }
    }

    public boolean discuss(MyItem item) throws IOException {
        URL obj = new URL(POST_URL + "discuss");
        HttpURLConnection con = (HttpURLConnection) obj.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);
        System.out.println(item.getFun_name());

        String userfrom = LoginDialog.getUserId();
        String payload = String.format("{\"userto\":\"%s\",\"userfrom\":\"%s\",\"funname\":\"%s\"}", item.getUser(), userfrom, item.getFun_name());
        System.out.println(payload);

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

            if (response.toString().contains("Success!")) {
                return true;
            } else {
                return false;
            }

        } else {
            System.out.println("POST request did not work.");
            return false;
        }
    }

    public void sendToDBrequest(short codeUnitSize, long fullHash,
                                byte specificHashAdditionalSize, long specificHash,
                                String libraryFamilyName, String libraryVersion,
                                String libraryVariant, String ghidraVersion,
                                LanguageID languageID, int languageVersion,
                                int languageMinorVersion, CompilerSpecID compilerSpecID, String funName,
                                long entryPoint, String tokgroup) throws IOException {

        URL url = new URL(POST_URL + "fid");
        String response = "";

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("POST");
        connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        connection.setRequestProperty("unique_id", LoginDialog.getUserId());

        connection.setRequestProperty("codeUnitSize", Short.toString(codeUnitSize));
        connection.setRequestProperty("fullHash", Long.toString(fullHash));
        connection.setRequestProperty("specificHashAdditionalSize", Byte.toString(specificHashAdditionalSize));
        connection.setRequestProperty("specificHash", Long.toString(specificHash));

        connection.setRequestProperty("libraryFamilyName", libraryFamilyName);
        connection.setRequestProperty("libraryVersion", libraryVersion);
        connection.setRequestProperty("libraryVariant", libraryVariant);

        connection.setRequestProperty("ghidraVersion", ghidraVersion);
        connection.setRequestProperty("languageID", languageID.toString());
        connection.setRequestProperty("languageVersion", Integer.toString(languageVersion));
        connection.setRequestProperty("languageMinorVersion", Integer.toString(languageMinorVersion));
        connection.setRequestProperty("compilerSpecID", compilerSpecID.toString());
        connection.setRequestProperty("funName", funName);
        connection.setRequestProperty("entryPoint", Long.toString(entryPoint));
        connection.setRequestProperty("codeC", Base64.getEncoder().encodeToString(tokgroup.getBytes(StandardCharsets.UTF_8)));
        connection.setDoOutput(true);
        System.out.println(connection.getResponseCode());

        if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
            InputStream con = connection.getInputStream();
            Reader result = new BufferedReader(new InputStreamReader(con, StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            for (int c; (c = result.read()) >= 0; ) {
                sb.append((char) c);
            }
            response = sb.toString();
            Msg.showInfo(getClass(), null, "Function uploaded", response);

        }
        if (connection.getResponseCode() == HttpURLConnection.HTTP_CONFLICT) {
            InputStream con = connection.getErrorStream();
            Reader result = new BufferedReader(new InputStreamReader(con, StandardCharsets.UTF_8));

            StringBuilder sb = new StringBuilder();
            for (int c; (c = result.read()) >= 0; ) {
                sb.append((char) c);
            }
            response = sb.toString();
            Msg.showError(getClass(), null, "Error", response);

        }
        if (connection.getResponseCode() == HttpURLConnection.HTTP_NOT_FOUND) {
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
