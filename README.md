This project is an extension to keycloak in order to enable complience
with https://hl7.org/fhir/uv/bulkdata/authorization/index.html


## Quick Start
Locally deploy the extended keycloak instance   by running:

    ./mvnw clean package
    docker-compose up -d

Exercise the client credentials flow with the 
following parameters

    node auth-cc.js --client-id=fhir_cc_client --client-secret=fhir_cc_client --authorization-url="http://localhost:9080/auth/realms/fhirdev" --audience="http://fhirdev/token" --launch=123v456 --scope="launch/patient patient/Patient.read"
