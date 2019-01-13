package org.dvaara.wso2.identity.oauth2.token.handler.clientauth.mutualtls;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.dcr.bean.ApplicationRegistrationRequest;
import org.wso2.carbon.identity.oauth.dcr.exception.DCRMException;
import org.wso2.carbon.identity.oauth.dcr.service.DCRMService;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.client.authentication.AbstractOAuthClientAuthenticator;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthnException;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static java.lang.String.format;
import static org.dvaara.wso2.identity.oauth2.token.handler.clientauth.mutualtls.utils.MutualTLSUtil.JAVAX_SERVLET_REQUEST_CERTIFICATE;

/**
 * This class is responsible for authenticating OAuth clients with Mutual TLS. The client will present
 * client certificate presented to the authorization server during TLS handshake. As a result of successful
 * validation of the certificate at web container, the certificate will be available in request attributes. This
 * authenticator will authenticate the client by matching the certificate presented during handshake against the
 * certificate registered for the client.
 */
public class SpiffeMTLSClientAuthenticator extends AbstractOAuthClientAuthenticator {

    private static Log log = LogFactory.getLog(SpiffeMTLSClientAuthenticator.class);

    /**
     * @param request                 HttpServletRequest which is the incoming request.
     * @param bodyParams              Body parameter map of the request.
     * @param oAuthClientAuthnContext OAuth client authentication context.
     * @return Whether the authentication is successful or not.
     * @throws OAuthClientAuthnException
     */
    @Override
    public boolean authenticateClient(HttpServletRequest request, Map<String, List> bodyParams,
                                      OAuthClientAuthnContext oAuthClientAuthnContext)
            throws OAuthClientAuthnException {

        if (log.isDebugEnabled()) {
            log.debug("Authenticating client with public certificate.");
        }

        X509Certificate requestCert;
        Object certObject = request.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE);
        if (certObject instanceof X509Certificate[]) {
            X509Certificate[] cert = (X509Certificate[]) certObject;
            requestCert = cert[0];
        } else if (certObject instanceof X509Certificate) {
            requestCert = (X509Certificate) certObject;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Could not find client certificate in required format for client: " +
                        oAuthClientAuthnContext.getClientId());
            }
//            return false;
        }

        if (log.isDebugEnabled()) {
//            logCertDetails(requestCert);
        }

        getClientId(request, bodyParams, oAuthClientAuthnContext);
        registerClient(request, bodyParams, oAuthClientAuthnContext);
        return true;

    }

    private void logCertDetails(X509Certificate requestCert) throws OAuthClientAuthnException {

        try {
            log.debug(format("Cert Issuer: %s", requestCert.getIssuerDN().toString()));
            requestCert.getSubjectAlternativeNames().forEach((name) -> log.debug(name));
            log.debug(format("NotAfter date of the certificate: %s", requestCert.getNotAfter()));
            log.debug(format("NotBefore date of the certificate: %s", requestCert.getNotBefore()));
        } catch (CertificateParsingException e) {
            log.error("Error occurred in parsing the certificate.");
            throw new OAuthClientAuthnException("Error occurred in parsing the certificate.", e.getMessage());
        }

    }

    private void getClientID(X509Certificate requestCert) throws OAuthClientAuthnException {

        try {
            Collection<List<?>> sanNames = requestCert.getSubjectAlternativeNames();
            log.info(sanNames.stream().findFirst().get().get(0).toString());
        } catch (CertificateParsingException e) {
            log.error("Error occurred in parsing the certificate.");
            throw new OAuthClientAuthnException("Error occurred in parsing the certificate.", e.getMessage());
        }
    }

    /**
     * Returns whether the incoming request can be authenticated or not using the given inputs.
     *
     * @param request    HttpServletRequest which is the incoming request.
     * @param bodyParams Body parameters present in the request.
     * @param context    OAuth2 client authentication context.
     * @return Whether client can be authenticated using this authenticator.
     */
    @Override
    public boolean canAuthenticate(HttpServletRequest request, Map<String, List> bodyParams,
                                   OAuthClientAuthnContext context) {

        if (validCertExistsAsAttribute(request)) {
            if (log.isDebugEnabled()) {
                log.debug("Client ID exists in request body parameters and a valid certificate found in request " +
                        "attributes. Hence returning true.");
            }
            return true;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Mutual TLS authenticator cannot handle this request. A valid certificate not found in request attributes.");
            }
            return true;
        }
    }

    @Override
    public String getClientId(HttpServletRequest httpServletRequest, Map<String, List> map, OAuthClientAuthnContext oAuthClientAuthnContext) throws OAuthClientAuthnException {

        String clientID = ("spiffe://example.org" + System.currentTimeMillis()).replace("://","_").
                replace(".","_")
                .substring(0,28);
        oAuthClientAuthnContext.setClientId(clientID);
        return clientID;
    }

    /**
     * Check for the existence of a valid certificate in required format in the request attribute map.
     *
     * @param request HttpServletRequest which is the incoming request.
     * @return Whether a certificate exists or not.
     */
    private boolean validCertExistsAsAttribute(HttpServletRequest request) {

        Object certObject = request.getAttribute(JAVAX_SERVLET_REQUEST_CERTIFICATE);
        return (certObject instanceof X509Certificate[] || certObject instanceof X509Certificate);
    }

    @Override
    public String getName() {

        return this.getClass().getSimpleName();
    }

    private void registerClient(HttpServletRequest httpServletRequest, Map<String, List> map, OAuthClientAuthnContext oAuthClientAuthnContext) {
        ApplicationRegistrationRequest applicationRegistrationRequest = new ApplicationRegistrationRequest();
        applicationRegistrationRequest.setClientName(oAuthClientAuthnContext.getClientId());
        applicationRegistrationRequest.setConsumerKey(oAuthClientAuthnContext.getClientId());
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setUsername("admin");
        ArrayList<String> grants = new ArrayList<>();
        grants.add("client_credentials");
        applicationRegistrationRequest.setGrantTypes(grants);
        try {
            getOAuth2DCRMService().registerApplication(applicationRegistrationRequest);
        } catch (DCRMException e) {
            e.printStackTrace();
        }

        log.info("Client Registered.");

    }

    public static DCRMService getOAuth2DCRMService() {

        return (DCRMService) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getOSGiService(DCRMService.class, null);
    }
}
