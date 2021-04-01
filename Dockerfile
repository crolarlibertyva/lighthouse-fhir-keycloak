FROM jboss/keycloak:12.0.4

COPY target/fhir-keycloak-*.jar /opt/jboss/keycloak/providers/fhir-keycloak.jar
