package org.example;

import org.json.JSONArray;
import org.json.JSONObject;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Iterator;

/*
    Class used to make the request to the vulnerabilities DB and return a JSON array with the cve's with all the info
 */
public class getCVE {

    private static final String ERROR_MESSAGE = "Connection to cve search DB failed.";
    private static final String URL_CVE = "https://api.cvesearch.com/search?q=keycloak";
    private Iterator cves;
    private Response resp;
    private String API_KEY;

    public getCVE() {
        resp=new Response();
        API_KEY=System.getenv("KC_VERIFIER_API_KEY");
    }

    public JSONArray get() throws IOException {
        URL url = new URL(URL_CVE);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("X-Api-Key", API_KEY);

        conn.setRequestProperty("Accept","*/*");

        String response="";
        try {
            response = resp.getResponse(conn);
        } catch (Exception a){
            System.out.println(ERROR_MESSAGE);
            return new JSONArray();
        }

        JSONObject json = new JSONObject(response);
        JSONObject cveJson = json.getJSONObject("response");
        return getAffectedCVEs(cveJson);
    }

    private JSONArray getAffectedCVEs(JSONObject response) {
        JSONArray objectsToReturn = new JSONArray();
        JSONObject object;
        String cve;
        Iterator temp;
        String product = "";
        cves = response.keys();
        while (cves.hasNext()) {
            cve = cves.next().toString();
            object= response.getJSONObject(cve);
            temp = response.getJSONObject(cve).getJSONArray("affected_products").iterator();
            while (temp.hasNext()) {
                product = temp.next().toString();
                String[] a = product.split(":");
                String producer = a[3];
                String prod = a[4];
                if (producer.equals("redhat") || producer.equals("keycloak")) {
                        if(prod.equals("keycloak"))
                                objectsToReturn.put(object);
                        }
                }
            }
        return objectsToReturn;
    }

}