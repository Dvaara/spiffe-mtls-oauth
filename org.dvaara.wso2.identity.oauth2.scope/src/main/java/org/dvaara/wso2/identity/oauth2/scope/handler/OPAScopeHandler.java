package org.dvaara.wso2.identity.oauth2.scope.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;
import org.dvaara.wso2.identity.oauth2.scope.utils.OPAScopeUtils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeHandler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

import static java.lang.String.format;

/**
 * Scope handler for token requests based on OPA policies.
 * This handles the scopes getting attached with an access token based on the policies defined in OPA engine.
 * Gives the intersection of scopes allowed for the client and what is requested by the client.
 */
public class OPAScopeHandler extends OAuth2ScopeHandler {

    private static Log log = LogFactory.getLog(OPAScopeHandler.class);

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        Set<String> clientRequestedScopes = Arrays.stream(tokReqMsgCtx.getScope()).collect(Collectors.toSet());
        if (log.isDebugEnabled()) {
            clientRequestedScopes.forEach((name) -> log.debug(format("Client requested scope: %s", name)));
        }

        Set<String> allowedScopes = getAllowedOPAScopes(tokReqMsgCtx);
        if (log.isDebugEnabled()) {
            clientRequestedScopes.forEach((name) -> log.debug(format("OPA allowed scope: %s", name)));
        }

        //get the intersection
        clientRequestedScopes.retainAll(allowedScopes);

        tokReqMsgCtx.setScope(clientRequestedScopes.stream().toArray(String[]::new));

        return true;
    }

    private Set<String> getAllowedOPAScopes(OAuthTokenReqMessageContext tokReqMsgCtx) {
        //By the time this method is called, clientID is validated.
        tokReqMsgCtx.getOauth2AccessTokenReqDTO().getoAuthClientAuthnContext().getClientId();
        tokReqMsgCtx.getOauth2AccessTokenReqDTO().getoAuthClientAuthnContext().isAuthenticated();
        tokReqMsgCtx.getOauth2AccessTokenReqDTO().getHttpRequestHeaders();  //user-agent

        return Collections.emptySet();
    }

    private String callOPA(String query) throws IOException {

        HttpResponse response =
                Request.Post(getOPAServerURL())
                        .bodyString(query, ContentType.APPLICATION_JSON)
                        .execute().returnResponse();
        String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        return json;
    }

    @Override
    public boolean canHandle(OAuthTokenReqMessageContext tokReqMsgCtx) {
        //Todo can check if OPA server configs are available.
        return true;
    }

    private String getOPAServerURL() {

        return getProperties().get(OPAScopeUtils.OPA_SERVER_URL);
    }

    private String getOPAServerUsername() {

        return getProperties().get(OPAScopeUtils.OPA_SERVER_USERNAME);
    }

    private char[] getOPAServerPassword() {

        return getProperties().get(OPAScopeUtils.OPA_SERVER_PASSWORD).toCharArray();
    }
}
