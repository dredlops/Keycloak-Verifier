/*
Keycloak Verifier. Plugin to search for vulnerabilities in Keycloak.
Copyright (C) 2023 Andre Sousa

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
*/

package org.example;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Iterator;

public class KeycloakVerifier {

    private String versionInUse;
    private static JSONArray cves;

    private static getVulnerabilityInRecords getVulnerabilityInRecords;

    private static produceReport produceReport;


    public KeycloakVerifier( String versionInUse) throws IOException, URISyntaxException {
        getVulnerabilityInRecords= new getVulnerabilityInRecords();
        produceReport = new produceReport();
        this.versionInUse=versionInUse;
        getCVE getCVE = new getCVE();
        cves = getCVE.get();
        verify();
        produceReport.writeReport();
    }

    private void verify() throws IOException, URISyntaxException {
        if(!cves.isEmpty()){
        Iterator it= cves.iterator();
        JSONObject cve;
        while (it.hasNext()) {
            cve = (JSONObject) it.next();
            JSONObject aux = getVulnerabilityInRecords.getVulnerability(cve.getJSONObject("threat_intel").getJSONObject("general").get("cve").toString());

            if (aux == null) {
                //Vulnerabilities missing on file vulnerabilities.log
                analyzeUnknownCVE(cve);
            } else{
                //Vulnerabilities on file vulnerabilities.log
                analyzeCVE(aux);
            }
        }
        } else {
            analyzeWithNoCve();
        }
    }


    //checks if are any vulnerabilities with this cve and version
    private void analyzeCVE(JSONObject cve) throws IOException{
        String good_version = cve.get("good_version").toString();
        if(isVersionInUseLessThen(good_version)){
            JSONObject jsonObject = getVulnerabilityInRecords.getVulnerability(cve.getString("cve"));
                //vulnerability found on the vulnerabilities file
                if(getVulnerabilityInRecords.hasVerificationAvailable(jsonObject.getString("cve").toString())){

                    boolean isActive=false;
                    //call a method that verifies if the vulnerability really occurs
                    switch (cve.getString("cve")){
                        case "CVE-2022-3782":
                            vulnerabilityThree v= new vulnerabilityThree();
                            isActive = v.vulnerabilityThree();
                            break;
                        case "CVE-2020-1717":
                            vulnerabilityOne v1= new vulnerabilityOne();
                            isActive= v1.vulnerabilityOne();
                            break;
                        case "CVE-2021-3754":
                            vulnerabilityTwo v2= new vulnerabilityTwo();
                            isActive=v2.vulnerabilityTwo();
                            break;
                        default:
                            vulnerabilityGeneral v3 = new vulnerabilityGeneral();
                            isActive=v3.vulnerabilityGeneral(cve.getString("cve"));
                            break;

                    }
                    if (isActive){
                        //Creates a warning
                        warning wrng = new warning();
                        String cveAux=cve.getString("cve");

                        String warning = wrng.addWarning(cve.getString("severity"),cve.getString("message"),cve.getString("solution")+" to "+ cve.getString("good_version"),cveAux);
                        produceReport.add(warning);
                    }
                } else{
                    //In this case there is no possible verification
                    //only produces a warning with info from vulnerabilities.log
                    warning wrng = new warning();
                    String cveAux=cve.getString("cve");
                    String warning = wrng.addWarning(cve.getString("severity"),cve.getString("message"),cve.getString("solution")+" to "+ cve.getString("good_version"),cveAux);
                    produceReport.add(warning);
                }
        }

    }


    private boolean isVersionInUseLessOrEqualThen(String version){
        String[] inUse = versionInUse.split("\\.");
        String[] vers = version.split("\\.");
        if(Integer.parseInt(inUse[0])<Integer.parseInt(vers[0])){
            return true;
        } else{
            if(Integer.parseInt(inUse[0])==Integer.parseInt(vers[0])){
                if(Integer.parseInt(inUse[1])<Integer.parseInt(vers[1]))
                    return true;
                else{
                    if(Integer.parseInt(inUse[1])==Integer.parseInt(vers[1])){
                        if(Integer.parseInt(inUse[2])<Integer.parseInt(vers[2]))
                            return true;
                        else if (Integer.parseInt(inUse[2])==Integer.parseInt(vers[2]))
                            return true;
                    }
                }
            }
        }
        return false;
    }
    private boolean isVersionInUseLessThen(String version){
        String[] inUse = versionInUse.split("\\.");
        String[] vers = version.split("\\.");
        if(Integer.parseInt(inUse[0])<Integer.parseInt(vers[0])){
            return true;
        } else{
            if(Integer.parseInt(inUse[0])==Integer.parseInt(vers[0])){
                if(Integer.parseInt(inUse[1])<Integer.parseInt(vers[1]))
                    return true;
                else{
                    if(Integer.parseInt(inUse[1])==Integer.parseInt(vers[1])){
                        if(Integer.parseInt(inUse[2])<Integer.parseInt(vers[2]))
                            return true;
                        else if (Integer.parseInt(inUse[2])==Integer.parseInt(vers[2]))
                            return false;
                    }
                }
            }
        }
        return false;
    }

    /*
    Analyze the cve's that are not on the vulnerabilities.log
     */
    private void analyzeUnknownCVE(JSONObject cve){
        String version=getVersionFixedFromCVE(cve);
        if(!version.equals("") && isVersionInUseLessOrEqualThen(version)) {
            warning wrng = new warning();
            String cveAux = cve.getJSONObject("threat_intel").getJSONObject("general").get("cve").toString();
            String severity = cve.getJSONObject("details").getString("severity");
            String message = cve.getJSONObject("basic").getString("description");
            String warning="";
            if(version.equals("")) {
                warning = wrng.addWarning(severity, message, "", cveAux);

            }
            else{
                String a = "This vulnerability was mitigated on version " + version;
                warning = wrng.addWarning(severity, message, a , cveAux);
            }
            produceReport.add(warning);
            }
        }


    private String getVersionFixedFromCVE(JSONObject cve){
        Iterator nodes = cve.getJSONObject("threat_intel").getJSONObject("general").getJSONObject("configurations").getJSONArray("nodes").iterator();
        JSONObject aux;
        while(nodes.hasNext()){
            aux= (JSONObject) nodes.next();
            Iterator matches = aux.getJSONArray("cpe_match").iterator();
            while (matches.hasNext()){
                JSONObject obj = (JSONObject) matches.next();
                String [] split = obj.getString("cpe23Uri").split(":");
                if(split[3].equals("redhat") || split[3].equals("keycloak"))
                    if(split[4].equals("keycloak")){
                        try{
                            return obj.getString("versionEndIncluding");
                        } catch (JSONException e){
                            return "";
                        }
                    }

            }
        }
        return "";
    }

    //In case there is no connection to DB
    //Gets all vulnerabilities in vulnerabilities.log and checks them against version in use
    private void analyzeWithNoCve() throws IOException, URISyntaxException {
        Iterator it =  getVulnerabilityInRecords.getAllVulnerabilities().iterator();
        while (it.hasNext()){
            analyzeCVE(((JSONObject) it.next()));
        }
    }

}
