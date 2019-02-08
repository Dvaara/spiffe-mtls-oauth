package org.dvaara.wso2.identity.oauth2.scope;

import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;

public class OPAScopeException extends IdentityOAuth2Exception {

    public OPAScopeException(String message) {

        super(message);
    }

    public OPAScopeException(String message, Throwable e) {

        super(message, e);
    }
}
