package org.example;

import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.utils.URLEncodedUtils;
import org.json.JSONObject;

import java.io.*;
//import java.net.HttpURLConnection;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import java.net.URLEncoder;
import java.util.Arrays;

public class getRequest {

    private static String HOST;
    private static String CLIENT;
    private static String PASSWORD;
    private static String USERNAME;
    private static final String URL_TOKEN = "realms/master/protocol/openid-connect/token";
    private static final String URL_VERSION = "admin/serverinfo";

    public getRequest(){
            PASSWORD=System.getenv("KC_VERIFIER_PASSWORD");
            USERNAME=System.getenv("KC_VERIFIER_USERNAME");
            CLIENT=System.getenv("KC_VERIFIER_CLIENT");
            HOST=System.getenv("KC_VERIFIER_HOST");
            disableSSLCertificateChecking();

            System.out.println("client=" + CLIENT);
            System.out.println("host=" + HOST);
            System.out.println("password=" + PASSWORD);
            System.out.println("username=" + USERNAME);
        }






    public String getToken() throws IOException, URISyntaxException {
        URL url = new URL(HOST+URL_TOKEN);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);
        //conn.setInstanceFollowRedirects(false);
        //URLEncoder.encode(USERNAME, "UTF-8");
        String jsonInputString = "username="+URLEncoder.encode(USERNAME, "UTF-8")+"&password="+URLEncoder.encode(PASSWORD, "UTF-8")+"&grant_type=password&client_id="+CLIENT;





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

    public String getVersion() throws IOException, URISyntaxException {
        String token = getToken();
        URL url = new URL(HOST+URL_VERSION);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + token);

        String response = getResponse(conn);
        JSONObject json = new JSONObject(response);
        String version = json.getJSONObject("systemInfo").getString("version");

        return version;
    }

    private String getResponse(HttpsURLConnection conn) {
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

    public String getHost(){
        return HOST;
    }

    /**
     * Disables the SSL certificate checking for new instances of {@link HttpsURLConnection} This has been created to
     * aid testing on a local box, not for use on production.
     */
    private static void disableSSLCertificateChecking() {
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                // Not implemented
            }

            @Override
            public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                // Not implemented
            }
        } };

        try {
            SSLContext sc = SSLContext.getInstance("TLS");

            sc.init(null, trustAllCerts, new java.security.SecureRandom());

            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        } catch (KeyManagementException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

}

