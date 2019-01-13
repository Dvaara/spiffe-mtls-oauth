/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License
 */

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
                log.debug("Mutual TLS bundle is activated");
            }

        } catch (Throwable e) {
            log.error("Error occurred while registering SpiffeMTLSClientAuthenticator.", e);
        }
    }
}
