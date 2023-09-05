package org.example;



import org.json.JSONObject;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

public class getRequest {

    private static String HOST;
    private static String CLIENT;
    private static String PASSWORD;
    private static String USERNAME;

    //private static final String FILE = ".properties";
    private static final String URL_TOKEN = "realms/master/protocol/openid-connect/token";
    private static final String URL_VERSION = "admin/serverinfo";

    public getRequest(String password, String username, String client, String host) throws IOException {
        PASSWORD=password;
        USERNAME=username;
        CLIENT=client;
        HOST=host;
    }

    public getRequest(){}

    public String getToken() throws IOException {
        URL url = new URL(HOST+URL_TOKEN);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);
        String jsonInputString = "username="+USERNAME+"&password="+PASSWORD+"&grant_type=password&client_id="+CLIENT;

        write();

        OutputStream os = conn.getOutputStream();
        byte[] input = jsonInputString.getBytes(StandardCharsets.UTF_8);
        os.write(input, 0, input.length);
        os.flush();
        os.close();
        String response = getResponse(conn);
        JSONObject obj = new JSONObject(response);
        String token = obj.getString("access_token");
        return token;
    }

    private void write(){
        try (FileWriter fileWriter = new FileWriter("log2.txt", true)) {
            fileWriter.write("Secret Value: " + HOST + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getVersion() throws IOException {
        String token = getToken();
        URL url = new URL(HOST+URL_VERSION);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + token);

        String response = getResponse(conn);
        JSONObject json = new JSONObject(response);
        String version = json.getJSONObject("systemInfo").getString("version");

        return version;
    }

    private String getResponse(HttpURLConnection conn) {
        BufferedReader in;
        String output;

        try {
            in = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        StringBuffer response = new StringBuffer();

        while (true) {
            try {
                if ((output = in.readLine()) == null) break;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            response.append(output);
        }

        try {
            in.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return response.toString();
    }

    /*private void setProperties() throws IOException {
        Properties prop = new Properties();
        FileInputStream ip = new FileInputStream(FILE);
        prop.load(ip);
        HOST=System.getProperty("host");
        //HOST=prop.getProperty("host");

    }*/
    public String getHost(){
        return HOST;
    }

}

