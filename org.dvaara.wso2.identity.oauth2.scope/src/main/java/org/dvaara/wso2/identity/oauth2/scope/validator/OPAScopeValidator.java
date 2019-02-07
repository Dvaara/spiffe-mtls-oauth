package org.dvaara.wso2.identity.oauth2.scope.validator;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.validators.OAuth2ScopeValidator;
import org.dvaara.wso2.identity.oauth2.scope.utils.OPAScopeUtils;

/**
 * Retrieve the decision from Open Policy Engine on whether the scopes attached to the token are
 * valid to access the resource under consideration.
 */
public class OPAScopeValidator extends OAuth2ScopeValidator{


    @Override
    public boolean validateScope(AccessTokenDO accessTokenDO, String s) throws IdentityOAuth2Exception {

        return false;
    }


    private String getOPAServerURL() {
        return getProperties().get(OPAScopeUtils.OPAServerURL);
    }

    private String getOPAServerUsername() {
        return getProperties().get(OPAScopeUtils.OPAServerUsername);
    }

    private char[] getOPAServerPassword() {
        return getProperties().get(OPAScopeUtils.OPAServerPassword).toCharArray();
    }
}
