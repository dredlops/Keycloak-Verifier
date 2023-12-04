/*
Keycloak Verifier. Plugin to search for vulnerabilities in Keycloak.
Copyright (C) 2023 Andre Sousa

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see https://www.gnu.org/licenses/.
*/

package org.example;


public class warning {

    /*
    severity will be mapped as severity
    description will be mapped as message
    solution will be mapped as description
    category will be mapped as category
     */
    private enum severity {HIGH, LOW, NORMAL};
    public warning(){}

    //Creates a warning in the specific format
    public String addWarning(String severity, String description, String solution, String cve){
        String s = "{\"message\":\""+("cve: "+cve+" "+description)+"\",\"severity\":\""+setSeverity(severity)+"\",\"description\":\""+solution+"\"}";
        return s;
    }

    //Turns the severity number into the recognized format
    private String setSeverity(String severity){
        String[] temp=severity.split("\\.");
        String sev;
        int digit1 = Integer.parseInt(temp[0]);
        int digit2 = Integer.parseInt(temp[1]);

        sev = String.valueOf(warning.severity.HIGH);
        if(digit1>3){
            if(digit1>6)
                sev = String.valueOf(warning.severity.HIGH);
            else {
                if(digit1==6){
                    if(digit2>5) sev = String.valueOf(warning.severity.HIGH);
                    else sev = String.valueOf(warning.severity.NORMAL);
                } else sev = String.valueOf(warning.severity.NORMAL);
            }
        }else {
            if(digit1==3 && digit2>5)
                sev = String.valueOf(warning.severity.NORMAL);
            else
                sev = String.valueOf(warning.severity.LOW);
        }
        return sev;
    }
}