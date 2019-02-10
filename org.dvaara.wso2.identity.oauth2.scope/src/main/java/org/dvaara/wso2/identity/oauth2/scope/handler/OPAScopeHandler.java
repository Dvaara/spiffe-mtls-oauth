package org.dvaara.wso2.identity.oauth2.scope.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;
import org.dvaara.wso2.identity.oauth2.scope.utils.OPAScopeUtils;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
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
    public static final String SPIFFE_ID = "spiffe-id";

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        log.info("Inside OPAScopeHandler");
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
        OAuth2AccessTokenReqDTO requestDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();

        if(!requestDTO.getoAuthClientAuthnContext().isAuthenticated()){
            return Collections.emptySet(); //If not authenticated, no use in checking on scopes.
        }

        String clientID = requestDTO.getoAuthClientAuthnContext().getClientId();
        String spiffeID = (String) requestDTO.getoAuthClientAuthnContext().getProperties().get(SPIFFE_ID);
        HttpRequestHeader[] requestHeaders = requestDTO.getHttpRequestHeaders();  //user-agent
        RequestParameter[] requestParams = requestDTO.getRequestParameters();

        if(log.isDebugEnabled()){
            Arrays.stream(requestHeaders).forEach(requestHeader ->
                    log.debug("Header:" + requestHeader.getName() +"+"+requestHeader.getValue()[0]));
            Arrays.stream(requestParams).forEach(requestParameter ->
                    log.debug("Param:"+ requestParameter.getKey()+" Value"+ requestParameter.getValue()[0]));
            log.debug(format("SPIFFE ID: %s , Client ID: %s", spiffeID, clientID));
        }

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
