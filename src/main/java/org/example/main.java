package org.example;


import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.IOException;

@Mojo(name="verifier", defaultPhase = LifecyclePhase.INITIALIZE)
public class main extends AbstractMojo {

    @Parameter(property = "HOST")
    private String HOST;
    @Parameter(property = "USERNAME")
    private String USERNAME;
    @Parameter(property = "PASSWORD")
    private String PASSWORD;
    @Parameter(property = "CLIENT")
    private String CLIENT;


    public void execute() {
        getRequest get;
        try {
            get = new getRequest(PASSWORD, USERNAME, CLIENT, HOST);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        try {
            String version = get.getVersion();
            new KeycloakVerifier(version);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
