package org.fhir.keycloak.client.authenticator;

import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.clientpolicy.executor.SecureClientAuthEnforceExecutorFactory;
import java.util.List;

public class SecureFhirClientAuthEnforceExecutorFactory extends SecureClientAuthEnforceExecutorFactory {

    private static final ProviderConfigProperty CLIENTAUTHNS_PROPERTY = new ProviderConfigProperty(
            CLIENT_AUTHNS, null, null, ProviderConfigProperty.MULTIVALUED_STRING_TYPE, null);
    private static final ProviderConfigProperty CLIENTAUTHNS_AUGMENT = new ProviderConfigProperty(
            CLIENT_AUTHNS_AUGMENT, null, null, ProviderConfigProperty.STRING_TYPE, JwtFhirClientAuthenticator.PROVIDER_ID);

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> l = super.getConfigProperties();
        l.add(CLIENTAUTHNS_PROPERTY);
        l.add(CLIENTAUTHNS_AUGMENT);
        return l;
    }
}
