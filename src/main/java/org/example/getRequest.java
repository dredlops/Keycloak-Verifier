/*
Keycloak Verifier. Plugin to search for vulnerabilities in Keycloak.
Copyright (C) 2023 Andre Sousa

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
*/

package org.example;

import org.json.JSONObject;

import java.io.*;
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
    }






    public String getToken() throws IOException{
        URL url = new URL(HOST+URL_TOKEN);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setDoOutput(true);

        conn.setRequestProperty("Accept","*/*");
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
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Authorization", "Bearer " + token);

        conn.setRequestProperty("Accept","*/*");

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

    public String getHost(){
        return HOST;
    }

    /**
     * Disables the SSL certificate checking for new instances of {@link HttpsURLConnection} This has been created to
     * aid testing on a local box, not for use on production.
     */
    public void disableSSLCertificateChecking() {
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

