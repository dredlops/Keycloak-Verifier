package org.example;


import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;

import java.io.IOException;

@Mojo(name="keycloakVerifier", defaultPhase = LifecyclePhase.INITIALIZE)
public class Main extends AbstractMojo {

    public void execute() {
        getRequest get;
        try {
            get = new getRequest();
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
