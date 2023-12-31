
# Keycloak Verifier

Keycloak Verifier is a plugin responsible for gathering the vulnerabilities present in Keycloak (Open Source Identity and Access Management). 

Not only is Keycloak Verifier ready to be integrated into Jenkins, with the Warnings Next Generation plugin, to produce an interface for users, but it is also possible to use Keycloak Verifier alone and look at the output file (output.log), which will contain JSON objects with the vulnerabilities found.


## Description

Keycloak Verifier arose from the need to detect possible vulnerabilities in Keycloak. 
This plugin detects the version of Keycloak in use, looks for CVEs that may be present in the instance, performs some checks and suggests possible solutions.
It has a simple database, which makes DB searches very quick.

## Environment Variables

To run this project, you will need to add the following environment variables to your .env file

`KC_VERIFIER_PASSWORD` -> password for Keycloak user

`KC_VERIFIER_USERNAME` -> username for Keycloak

`KC_VERIFIER_CLIENT` -> keycloak client

`KC_VERIFIER_HOST` -> url of Keycloak instance (must end with /)

`KC_VERIFIER_API_KEY` -> API Key for CVE search API


These can also be declared in Jenkins.

## CVE Search API

In order to obtain the existing vulnerabilities, the plugin will use the API described at the following link: https://docs.cvesearch.com.
Through this API it will be possible to update known vulnerabilities, although its use is not mandatory, since the project already includes a small database with the vulnerabilities known to date.
However, in order to use the API it will be necessary to request an API-KEY, as can be seen in the API documentation.

## Deployment

To deploy this project run

```bash
  mvn clean install 
  mvn org.example:teste-plugin:test
```
To run this plugin it is necessary to create a Client in Keycloak, with "view-clients" and "view-realm" roles.

## Jenkins

First, in Jenkins, add Warnings Next Generation to your plugins.

To run the plugin in Jenkins it is necessary to add in the "Build" stage, the code to access the repository and compile the code, something like:

```code
git url: 'https://github.com/dredlops/KeycloakVerifier.git', branch: 'main'
sh 'mvn clean install'
sh 'mvn org.example:teste-plugin:test'
```
In another stage it is then necessary to add a step that will run Warnings NG, such as:
```code
withCredentials([usernamePassword(credentialsId: 'keycloakUser', passwordVariable: 'KC_VERIFIER_PASSWORD', usernameVariable: 'KC_VERIFIER_USERNAME')]) {
                  recordIssues( enabledForFailure: true, aggregatingResults: true, tools: [issues(pattern: '**/output.log', reportEncoding: 'UTF-8')] )
```

In this example, the credentials for the Keycloak user have been stored in "keycloakUser", as username/password. These credentials are passed to Warnings NG via "recordIssues". 

Here is an example of a simple pipeline script that will run the code from the repository and show the report on Warnings NG:
```code
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                // Get some code from a GitHub repository
                git url: 'https://github.com/dredlops/KeycloakVerifier.git', branch: 'main'
                sh 'mvn clean install'
                sh 'mvn org.example:teste-plugin:test'
            }
        }
        stage('Analysis') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'keycloakUser', passwordVariable: 'KC_VERIFIER_PASSWORD', usernameVariable: 'KC_VERIFIER_USERNAME')]) {
                  recordIssues( enabledForFailure: true, aggregatingResults: true, tools: [issues(pattern: '**/output.log', reportEncoding: 'UTF-8')] )
                }
            }
        }
    }
}
```
## Interface Example

Here is an example from Warnings NG in Jenkins, running Keycloak Verifier.

![alt text](https://github.com/dredlops/Keycloak-Verifier/blob/main/g.png)
## Authors

- [@dredlops](https://www.github.com/dredlops)


## Run Locally

Clone the project

```bash
  git clone https://github.com/dredlops/Keycloak-Verifier.git
```

Install Plugin

```bash
  mvn clean install
```

Run Plugin

```bash
  mvn org.example:teste-plugin:test
```

But first, create a ".properties" file with the environment variables.  
## License

[GNU](https://choosealicense.com/licenses/gpl-3.0/)

