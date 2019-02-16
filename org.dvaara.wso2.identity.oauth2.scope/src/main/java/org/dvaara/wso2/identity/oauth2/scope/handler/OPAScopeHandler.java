package org.dvaara.wso2.identity.oauth2.scope.handler;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.dvaara.wso2.identity.oauth2.scope.utils.OPAScopeUtils;
import org.json.JSONObject;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.HttpRequestHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeHandler;
import org.json.JSONObject;


import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
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

        Set<String> allowedScopes = null;
        try {
            allowedScopes = getAllowedOPAScopes(tokReqMsgCtx);
        } catch (IOException e) {
            throw new IdentityOAuth2Exception("Failed to get decision from OPA endpoint.", e);
        }
        if (log.isDebugEnabled()) {
            clientRequestedScopes.forEach((name) -> log.debug(format("OPA allowed scope: %s", name)));
        }

        //get the intersection
        clientRequestedScopes.retainAll(allowedScopes);

        tokReqMsgCtx.setScope(clientRequestedScopes.stream().toArray(String[]::new));

        return true;
    }

    private Set<String> getAllowedOPAScopes(OAuthTokenReqMessageContext tokReqMsgCtx) throws IOException {
        //By the time this method is called, clientID is validated.
        OAuth2AccessTokenReqDTO requestDTO = tokReqMsgCtx.getOauth2AccessTokenReqDTO();

        if(!requestDTO.getoAuthClientAuthnContext().isAuthenticated()){
            return Collections.emptySet(); //If not authenticated, no use in checking on scopes.
        }

        String clientID = requestDTO.getoAuthClientAuthnContext().getClientId();
        String spiffeID = (String) requestDTO.getoAuthClientAuthnContext().getProperties().get(SPIFFE_ID);
        HttpRequestHeader[] requestHeaders = requestDTO.getHttpRequestHeaders();  //user-agent
        RequestParameter[] requestParams = requestDTO.getRequestParameters();

        Map<String,Object> inputDictionary = new HashMap<>();
        inputDictionary.put(OPAScopeUtils.CLIENT_ID, clientID);
        inputDictionary.put(OPAScopeUtils.SPIFFE_ID, spiffeID);
        Arrays.stream(requestHeaders).forEach(header -> inputDictionary.put(header.getName(), header.getValue()));
        Arrays.stream(requestParams).forEach(parameter -> inputDictionary.put(parameter.getKey(), parameter.getValue()));

//        String json = new ObjectMapper().writeValueAsString(inputDictionary);
        String json = new Gson().toJson(inputDictionary);

        if(log.isDebugEnabled()){
            inputDictionary.entrySet().stream().forEach(entry -> log.debug("Key:" + entry.getKey() +", Value: "+ entry.getValue()));
        }

        return callOPA(spiffeID,json);
    }

    private Set<String> callOPA(String spiffeID, String query) throws IOException {

        Set<String> allowedSet = new HashSet<>();

        String encodedSpiffeID = URLEncoder.encode(String.format("data.scopes[i].id = \"%s\"  data.scopes[i].scopes= response",spiffeID), "UTF-8");
        log.debug(encodedSpiffeID);
        DefaultHttpClient httpClient = new DefaultHttpClient();
        HttpGet getRequest = new HttpGet("http://192.168.0.1:8181/v1/query?q="+ encodedSpiffeID);
        HttpResponse httpResponse = httpClient.execute(getRequest);

//        HttpResponse response = Request.Get("http://localhost:8181/v1/query?q="+encodedSpiffeID)
//                .addHeader("Content-Type",ContentType.APPLICATION_FORM_URLENCODED.toString()).execute().returnResponse();
        if(httpResponse.getStatusLine().getStatusCode() == 200) {
            String json = EntityUtils.toString(httpResponse.getEntity(), StandardCharsets.UTF_8);
            JsonParser parser = new JsonParser();
            JsonElement jsonObject = parser.parse(json);
            JsonArray allowedScopes = ((JsonObject) jsonObject).getAsJsonArray("result").get(0).getAsJsonObject().get("response").getAsJsonArray();
            Gson gson = new Gson();
            String[] output = gson.fromJson(allowedScopes , String[].class);

            allowedSet = new HashSet<>(Arrays.asList(output));

            log.info(String.format("Allowed set of scopes as per OPA : %s", allowedSet.toString()));
        } else {
            log.error("Error in getting decision from OPA. Returning zero scopes.");
            allowedSet = Collections.emptySet();
        }
//                Request.Post(getOPAServerURL())
//                        .bodyString(query, ContentType.APPLICATION_JSON)
//                        .execute().returnResponse();
//        String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
//        log.debug("Decision from OPA :" + json);

        return allowedSet;
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
