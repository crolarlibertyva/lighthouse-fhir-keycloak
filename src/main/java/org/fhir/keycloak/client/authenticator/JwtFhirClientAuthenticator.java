package org.fhir.keycloak.client.authenticator;

import java.security.PublicKey;
import java.util.Arrays;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.ClientAuthenticationFlowContext;
import org.keycloak.authentication.authenticators.client.ClientAuthUtil;
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator;
import org.keycloak.common.util.Time;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SingleUseTokenStoreProvider;
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;

public class JwtFhirClientAuthenticator extends JWTClientAuthenticator {
    private static final Logger logger = Logger.getLogger(JwtFhirClientAuthenticator.class);

    @Override
    public void authenticateClient(ClientAuthenticationFlowContext context) {
        MultivaluedMap<String, String> params = context.getHttpRequest().getDecodedFormParameters();

        String clientAssertionType = params.getFirst(OAuth2Constants.CLIENT_ASSERTION_TYPE);
        String clientAssertion = params.getFirst(OAuth2Constants.CLIENT_ASSERTION);

        if (clientAssertionType == null) {
            Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "Parameter client_assertion_type is missing");
            context.challenge(challengeResponse);
            return;
        }

        if (!clientAssertionType.equals(OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT)) {
            Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "Parameter client_assertion_type has value '"
                    + clientAssertionType + "' but expected is '" + OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT + "'");
            context.challenge(challengeResponse);
            return;
        }

        if (clientAssertion == null) {
            Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "client_assertion parameter missing");
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challengeResponse);
            return;
        }

        try {
            JWSInput jws = new JWSInput(clientAssertion);
            JsonWebToken token = jws.readJsonContent(JsonWebToken.class);

            RealmModel realm = context.getRealm();
            String clientId = token.getSubject();
            if (clientId == null) {
                throw new RuntimeException("Can't identify client. Subject missing on JWT token");
            }

            if (!clientId.equals(token.getIssuer())) {
                throw new RuntimeException("Issuer mismatch. The issuer should match the subject");
            }

            context.getEvent().client(clientId);
            ClientModel client = realm.getClientByClientId(clientId);
            if (client == null) {
                context.failure(AuthenticationFlowError.CLIENT_NOT_FOUND, null);
                return;
            } else {
                context.setClient(client);
            }

            if (!client.isEnabled()) {
                context.failure(AuthenticationFlowError.CLIENT_DISABLED, null);
                return;
            }

            String expectedSignatureAlg = OIDCAdvancedConfigWrapper.fromClientModel(client).getTokenEndpointAuthSigningAlg();
            if (jws.getHeader().getAlgorithm() == null || jws.getHeader().getAlgorithm().name() == null) {
                Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "invalid signature algorithm");
                context.challenge(challengeResponse);
                return;
            }

            String actualSignatureAlg = jws.getHeader().getAlgorithm().name();
            if (expectedSignatureAlg != null && !expectedSignatureAlg.equals(actualSignatureAlg)) {
                Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), "invalid_client", "invalid signature algorithm");
                context.challenge(challengeResponse);
                return;
            }

            // Get client key and validate signature
            PublicKey clientPublicKey = getSignatureValidationKey(client, context, jws);
            if (clientPublicKey == null) {
                // Error response already set to context
                return;
            }

            boolean signatureValid;
            try {
                JsonWebToken jwt = context.getSession().tokens().decodeClientJWT(clientAssertion, client, JsonWebToken.class);
                signatureValid = jwt != null;
            } catch (RuntimeException e) {
                Throwable cause = e.getCause() != null ? e.getCause() : e;
                throw new RuntimeException("Signature on JWT token failed validation", cause);
            }
            if (!signatureValid) {
                throw new RuntimeException("Signature on JWT token failed validation");
            }

            // Allow both "issuer" or "token-endpoint" as audience
            String issuerUrl = Urls.realmIssuer(context.getUriInfo().getBaseUri(), realm.getName());
            String tokenUrl = OIDCLoginProtocolService.tokenUrl(context.getUriInfo().getBaseUriBuilder()).build(realm.getName()).toString();
            if (!token.hasAudience(issuerUrl) && !token.hasAudience(tokenUrl) && hasAcceptableAudience(token, realm.getName())) {
                throw new RuntimeException("Token audience doesn't match domain. Realm issuer is '" + issuerUrl + "' but audience from token is '" + Arrays.asList(token.getAudience()).toString() + "'");
            }

            if (!token.isActive()) {
                throw new RuntimeException("Token is not active");
            }

            // KEYCLOAK-2986
            int currentTime = Time.currentTime();
            if (token.getExpiration() == 0 && token.getIssuedAt() + 10 < currentTime) {
                throw new RuntimeException("Token is not active");
            }

            if (token.getId() == null) {
                throw new RuntimeException("Missing ID on the token");
            }

            SingleUseTokenStoreProvider singleUseCache = context.getSession().getProvider(SingleUseTokenStoreProvider.class);
            int lifespanInSecs = Math.max(token.getExpiration() - currentTime, 10);
            if (singleUseCache.putIfAbsent(token.getId(), lifespanInSecs)) {
                logger.tracef("Added token '%s' to single-use cache. Lifespan: %d seconds, client: %s", token.getId(), lifespanInSecs, clientId);

            } else {
                logger.warnf("Token '%s' already used when authenticating client '%s'.", token.getId(), clientId);
                throw new RuntimeException("Token reuse detected");
            }

            context.success();
        } catch (Exception e) {
            ServicesLogger.LOGGER.errorValidatingAssertion(e);
            Response challengeResponse = ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.getStatusCode(), OAuthErrorException.INVALID_CLIENT, "Client authentication with signed JWT failed: " + e.getMessage());
            context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, challengeResponse);
        }
    }

    private boolean hasAcceptableAudience(JsonWebToken jwt, String realmName) {
        for (String aud : jwt.getAudience()) {
            if (aud.contains(realmName) && aud.endsWith("token")) {
                logger.info("Token has acceptable audience assertion");
                return true;
            }
        }
        return  false;
    }
}
