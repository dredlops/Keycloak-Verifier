package org.example;


import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.IOException;
import java.net.URISyntaxException;

@Mojo(name="keycloakVerifier", defaultPhase = LifecyclePhase.INITIALIZE)
public class main extends AbstractMojo {


    public void execute() {
        getRequest get;
        get = new getRequest();
        try {
            String version = get.getVersion();
            new KeycloakVerifier(version);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

}
