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
        String s = "{\"message\":\""+description+"\",\"severity\":\""+setSeverity(severity)+"\",\"description\":\""+solution+"\",\"filename\":\""+cve+"\"}";
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