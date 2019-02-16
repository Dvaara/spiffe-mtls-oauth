package org.dvaara.wso2.identity.oauth2.scope.validator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.dvaara.wso2.identity.oauth2.scope.utils.OPAScopeUtils;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2TokenValidator;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import static java.lang.String.format;

/**
 * Retrieve the decision from Open Policy Engine on whether the scopes attached to the token are
 * valid to access the resource under consideration.
 */
public class OPATokenValidator extends DefaultOAuth2TokenValidator {

    private static Log log = LogFactory.getLog(OPATokenValidator.class);
    private static final String ACCESS_TOKEN_DO = "AccessTokenDO";
    private static final String RESOURCE = "resource";
    public static final String JAVAX_SERVLET_REQUEST_CERTIFICATE = "javax.servlet.request.X509Certificate";
    private static final String OPA_SERVER_URL = "";

    /**
     * Validate scope of the access token using OPA policies overriding the scope validators
     * registered so far. (We can't use the next level validators as only the accesstoken details are passed to them.)
     * Hence overriding all those in next level and only depends on OPA policies.
     *
     * @param messageContext Message context of the token validation request
     * @return Whether validation success or not
     * @throws IdentityOAuth2Exception Exception during while validation
     */
    @Override
    public boolean validateScope(OAuth2TokenValidationMessageContext messageContext) throws IdentityOAuth2Exception {

        log.info("Inside OPATokenValidator.");
        AccessTokenDO accessTokenDO = (AccessTokenDO) messageContext.getProperty(ACCESS_TOKEN_DO);

        String clientID = null;
        OAuthAppDO app;
        Map<String, Object> inputDictionary = new HashMap<>();
        Map<String, Object> inputDictionaryNested = new HashMap<>();
        String resource = null;
        String appOwner = null;
        boolean decision = false;
        try {
            clientID = accessTokenDO.getConsumerKey();
            app = OAuth2Util.getAppInformationByClientId(clientID);
            appOwner = app.getUser().getUsernameAsSubjectIdentifier(true, true);
            resource = getResourceFromMessageContext(messageContext);
            Arrays.stream(messageContext.getRequestDTO().getContext())
                    .forEach(param -> inputDictionary.put(param.getKey(), param.getValue()));
            inputDictionary.put(OPAScopeUtils.APP_OWNER, appOwner);
            inputDictionary.put(OPAScopeUtils.RESOURCE, resource);
            inputDictionary.put(OPAScopeUtils.CLIENT_ID, clientID);
            inputDictionary.put(OPAScopeUtils.SCOPE, accessTokenDO.getScope());
            Arrays.stream(accessTokenDO.getScope()).forEach(scope -> log.info("DO scope :" + scope));
            inputDictionary.put(OPAScopeUtils.ISSUED_TIME, String.valueOf(accessTokenDO.getIssuedTime()));

            inputDictionaryNested.put("input", inputDictionary);

            inputDictionary.entrySet().stream().forEach(entry -> log.info("Key:" + entry.getKey() +", Value: "+ entry.getValue()));
            String json = new ObjectMapper().writeValueAsString(inputDictionaryNested);
            log.info(json);
            decision = callOPA(json);

        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(String.format("Exception occurred when getting app information for " +
                    "client id %s ", accessTokenDO.getConsumerKey()), e);
        } catch (JsonProcessingException e) {
            throw new IdentityOAuth2Exception("Error occurred in passing the input dictionary.");
        } catch (IOException e) {
            throw new IdentityOAuth2Exception("Error occurred calling the OPA engine. Not passing the request.");
        }

        return decision;
    }

    private boolean callOPA(String json) throws IOException {

        DefaultHttpClient httpClient = new DefaultHttpClient();
        String url = "http://192.168.0.1:8181/v1/data/httpapi/authz";

        HttpPost post = new HttpPost(url);
        StringEntity requestEntity = new StringEntity(
                json,
                "application/json",
                "UTF-8");
        post.setEntity(requestEntity);
        post.setHeader("Content-Type", "application/x-www-form-urlencoded");
        post.setHeader("Method", "POST");
//            if (data.contains("token=")) {
        post.setHeader("Resource", "/finance/salary");
//            }
        boolean response = makeCall(httpClient, post);
        log.info("OPA decision:"+ response);

//        HttpResponse response =
//                Request.Post(OPA_SERVER_URL)
//                        .bodyString(query, ContentType.APPLICATION_JSON)
//                        .execute().returnResponse();
//        String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
//        return json;
        return response;
    }

    private static boolean makeCall(CloseableHttpClient httpClient, HttpPost post) {

        try {
            CloseableHttpResponse response = httpClient.execute(post);
            HttpEntity entity = response.getEntity();

            boolean isAllowed = false;
            if(response.getStatusLine().getStatusCode() == 200) {
                String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
                JsonParser parser = new JsonParser();
                JsonElement jsonObject = parser.parse(json);
                log.info(jsonObject.toString());
                isAllowed = ((JsonObject) jsonObject).get("result").getAsJsonObject().get("allow").getAsBoolean();;

//                allowedSet = new HashSet<>(Arrays.asList(output));

//                log.info(String.format("Allowed set of scopes as per OPA : %s", allowedSet.toString()));
            } else {
                log.info("Error in getting decision from OPA. Returning zero scopes.");
//                allowedSet = Collections.emptySet();
            }
            return isAllowed;
        } catch (IOException var4) {
            var4.printStackTrace();
            return false;
        }
    }

    /**
     * Extract the resource from the access token validation request message
     *
     * @param messageContext Message context of the token validation request
     * @return resource
     */
    private String getResourceFromMessageContext(OAuth2TokenValidationMessageContext messageContext) {

        String resource = null;
        if (messageContext.getRequestDTO().getContext() != null) {
            // Iterate the array of context params to find the 'resource' context param.
            for (OAuth2TokenValidationRequestDTO.TokenValidationContextParam resourceParam :
                    messageContext.getRequestDTO().getContext()) {
                // If the context param is the resource that is being accessed
                if (resourceParam != null && RESOURCE.equals(resourceParam.getKey())) {
                    resource = resourceParam.getValue();
                    break;
                }
            }
        }
        return resource;
    }

}
