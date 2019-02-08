package org.dvaara.wso2.identity.oauth2.scope.validator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpResponse;
import org.apache.http.client.fluent.Request;
import org.apache.http.entity.ContentType;
import org.apache.http.util.EntityUtils;
import org.dvaara.wso2.identity.oauth2.scope.utils.OPAScopeUtils;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.oauth2.validators.DefaultOAuth2TokenValidator;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Retrieve the decision from Open Policy Engine on whether the scopes attached to the token are
 * valid to access the resource under consideration.
 */
public class OPAScopeValidator extends DefaultOAuth2TokenValidator {

    private static Log log = LogFactory.getLog(OPAScopeValidator.class);
    private static final String ACCESS_TOKEN_DO = "AccessTokenDO";
    private static final String RESOURCE = "resource";
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

        AccessTokenDO accessTokenDO = (AccessTokenDO) messageContext.getProperty(ACCESS_TOKEN_DO);
        String clientID = null;
        OAuthAppDO app;
        Map<String, String> inputDictionary = new HashMap<>();
        String resource = null;
        String appOwner = null;
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

        } catch (InvalidOAuthClientException e) {
            throw new IdentityOAuth2Exception(String.format("Exception occurred when getting app information for " +
                    "client id %s ", accessTokenDO.getConsumerKey()), e);
        }

        return true;
    }

    private String callOPA(String query) throws IOException {

        HttpResponse response =
                Request.Post(OPA_SERVER_URL)
                        .bodyString(query, ContentType.APPLICATION_JSON)
                        .execute().returnResponse();
        String json = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);
        return json;
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
