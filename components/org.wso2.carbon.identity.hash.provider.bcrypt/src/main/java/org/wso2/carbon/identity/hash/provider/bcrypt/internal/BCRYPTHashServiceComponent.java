/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
 * under the License.
 */

package org.wso2.carbon.identity.hash.provider.bcrypt.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.hash.provider.bcrypt.BCRYPTHashProviderFactory;
import org.wso2.carbon.user.core.hash.HashProviderFactory;

/**
 * This class contains the BCRYPT hashing service component.
 */
@Component(
        name = "org.wso2.carbon.identity.hash.provider.bcrypt.component",
        immediate = true
)
public class BCRYPTHashServiceComponent {

    private static final Log log = LogFactory.getLog(BCRYPTHashServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            HashProviderFactory hashProviderFactory = new BCRYPTHashProviderFactory();
            ctxt.getBundleContext().registerService(HashProviderFactory.class.getName(),
                    hashProviderFactory, null);

            if (log.isDebugEnabled()) {
                log.debug("BCRYPT bundle activated successfully.");
            }
        } catch (Throwable e) {
            log.error("Failed to activate PBKDF bundle", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("BCRYPT bundle is deactivated ");
        }
    }
}
