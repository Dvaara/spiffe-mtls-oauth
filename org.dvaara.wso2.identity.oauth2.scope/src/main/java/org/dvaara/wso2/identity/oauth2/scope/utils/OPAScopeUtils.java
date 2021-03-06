package org.dvaara.wso2.identity.oauth2.scope.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Util class for OAuth 2.0 client authentication using Mutual TLS.
 */
public class OPAScopeUtils {

    private static Log log = LogFactory.getLog(OPAScopeUtils.class);
    public static final String OPA_SERVER_URL = "OPA.Server.URL";
    public static final String OPA_SERVER_PASSWORD = "OPA.Server.Password";
    public static final String OPA_SERVER_USERNAME = "OPA.Server.Username";
    public static final String RESOURCE = "resource";
    public static final String APP_OWNER = "app_owner";
    public static final String CLIENT_ID = "client_id";
    public static final String SPIFFE_ID = "spiffe_id";
    public static final String SCOPE = "scope";
    public static final String ISSUED_TIME = "iat";
    public static final String METHOD = "method";

}
