package org.dvaara.wso2.identity.oauth2.token.handler.clientauth.mutualtls.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.dvaara.wso2.identity.oauth2.token.handler.clientauth.mutualtls.SpiffeMTLSClientAuthenticator;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.wso2.carbon.identity.oauth2.client.authentication.OAuthClientAuthenticator;

/**
 * TLS Mutual Auth osgi Component.
 */
@Component(
        name = "org.dvaara.wso2.identity.oauth2.token.handler.clientauth.mutualtls",
        immediate = true
)
public class SpiffeMTLSServiceComponent {

    private static Log log = LogFactory.getLog(SpiffeMTLSServiceComponent.class);
    private BundleContext bundleContext;

    @Activate
    protected void activate(ComponentContext context) {

        try {
            // Registering SpiffeMTLSClientAuthenticator as an OSGIService.
            bundleContext = context.getBundleContext();
            SpiffeMTLSClientAuthenticator spiffeMTLSClientAuthenticator = new SpiffeMTLSClientAuthenticator();
            bundleContext.registerService(OAuthClientAuthenticator.class.getName(), spiffeMTLSClientAuthenticator,
                    null);
            if (log.isDebugEnabled()) {
                log.debug("SPIFFE Mutual TLS bundle is activated");
            }

        } catch (Throwable e) {
            log.error("Error occurred while registering SpiffeMTLSClientAuthenticator.", e);
        }
    }
}
