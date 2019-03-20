/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.models.sessions.infinispan;

import org.infinispan.client.hotrod.exceptions.HotRodClientException;
import org.infinispan.commons.api.BasicCache;
import org.jboss.logging.Logger;
import org.keycloak.common.util.Time;
import org.keycloak.models.*;
import org.keycloak.models.sessions.infinispan.entities.ActionTokenValueEntity;

import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:h2-wada@nri.co.jp">Hiroyuki Wada</a>
 */
public class InfinispanOAuth2DeviceTokenStoreProvider implements OAuth2DeviceTokenStoreProvider {

    public static final Logger logger = Logger.getLogger(InfinispanOAuth2DeviceTokenStoreProvider.class);

    private final Supplier<BasicCache<String, ActionTokenValueEntity>> codeCache;
    private final KeycloakSession session;

    public InfinispanOAuth2DeviceTokenStoreProvider(KeycloakSession session, Supplier<BasicCache<String, ActionTokenValueEntity>> actionKeyCache) {
        this.session = session;
        this.codeCache = actionKeyCache;
    }

    @Override
    public OAuth2DeviceCodeModel get(RealmModel realm, ClientModel client, String deviceCode) {
        try {
            // TODO limit slot
            BasicCache<String, ActionTokenValueEntity> cache = codeCache.get();
            ActionTokenValueEntity existing = cache.get(OAuth2DeviceCodeModel.createKey(realm.getId(), deviceCode));

            if (existing == null) {
                return null;
            }

            return OAuth2DeviceCodeModel.fromCache(realm.getId(), deviceCode, existing.getNotes());
        } catch (HotRodClientException re) {
            // No need to retry. The hotrod (remoteCache) has some retries in itself in case of some random network error happened.
            // In case of lock conflict, we don't want to retry anyway as there was likely an attempt to remove the code from different place.
            if (logger.isDebugEnabled()) {
                logger.debugf(re, "Failed when getting device code %s", deviceCode);
            }

            return null;
        }
    }

    @Override
    public void close() {

    }

    @Override
    public void create(OAuth2DeviceCodeModel deviceCode, OAuth2DeviceUserCodeModel userCode, int lifespanSeconds) {
        ActionTokenValueEntity deviceCodeValue = new ActionTokenValueEntity(deviceCode.serializeValue());
        ActionTokenValueEntity userCodeValue = new ActionTokenValueEntity(userCode.serializeValue());

        try {
            BasicCache<String, ActionTokenValueEntity> cache = codeCache.get();
            cache.put(deviceCode.serializeKey(), deviceCodeValue, lifespanSeconds, TimeUnit.SECONDS);
            cache.put(userCode.serializeKey(), userCodeValue, lifespanSeconds, TimeUnit.SECONDS);
        } catch (HotRodClientException re) {
            // No need to retry. The hotrod (remoteCache) has some retries in itself in case of some random network error happened.
            if (logger.isDebugEnabled()) {
                logger.debugf(re, "Failed when adding device code %s and user code %s",
                        deviceCode.getDeviceCode(), userCode.getUserCode());
            }
            throw re;
        }
    }

    @Override
    public boolean checkPollingInterval(OAuth2DeviceCodeModel deviceCode, int nextIntervalSeconds) {
        try {
            BasicCache<String, ActionTokenValueEntity> cache = codeCache.get();
            String key = deviceCode.serializeKey() + ".polling";
            ActionTokenValueEntity value = new ActionTokenValueEntity(null);
            ActionTokenValueEntity existing = cache.putIfAbsent(key, value, nextIntervalSeconds, TimeUnit.SECONDS);
            return existing == null;
        } catch (HotRodClientException re) {
            // No need to retry. The hotrod (remoteCache) has some retries in itself in case of some random network error happened.
            // In case of lock conflict, we don't want to retry anyway as there was likely an attempt to remove the code from different place.
            if (logger.isDebugEnabled()) {
                logger.debugf(re, "Failed when putting polling key for device code %s", deviceCode.getDeviceCode());
            }

            return false;
        }
    }

    @Override
    public OAuth2DeviceCodeModel get(RealmModel realm, String userCode) {
        try {
            OAuth2DeviceCodeModel deviceCode = findDeviceCodeByUserCode(realm, userCode);
            if (deviceCode == null) {
                return null;
            }

            return deviceCode;
        } catch (HotRodClientException re) {
            // No need to retry. The hotrod (remoteCache) has some retries in itself in case of some random network error happened.
            // In case of lock conflict, we don't want to retry anyway as there was likely an attempt to remove the code from different place.
            if (logger.isDebugEnabled()) {
                logger.debugf(re, "Failed when getting device code by user code %s", userCode);
            }

            return null;
        }
    }

    @Override
    public boolean verify(RealmModel realm, ClientModel client, String userCode) {
        try {
            // TODO limit slot
            BasicCache<String, ActionTokenValueEntity> cache = codeCache.get();
            String key = OAuth2DeviceUserCodeModel.createKey(realm.getId(), userCode);
            ActionTokenValueEntity existing = cache.get(key);
            return existing != null;
        } catch (HotRodClientException re) {
            // No need to retry. The hotrod (remoteCache) has some retries in itself in case of some random network error happened.
            // In case of lock conflict, we don't want to retry anyway as there was likely an attempt to remove the code from different place.
            if (logger.isDebugEnabled()) {
                logger.debugf(re, "Failed when getting user code %s", userCode);
            }

            return false;
        }
    }

    private OAuth2DeviceCodeModel findDeviceCodeByUserCode(RealmModel realm, String userCode) {
        BasicCache<String, ActionTokenValueEntity> cache = codeCache.get();
        String userNameKey = OAuth2DeviceUserCodeModel.createKey(realm.getId(), userCode);
        ActionTokenValueEntity existing = cache.get(userNameKey);

        if (existing == null) {
            return null;
        }

        OAuth2DeviceUserCodeModel data = OAuth2DeviceUserCodeModel.fromCache(realm.getId(), userCode, existing.getNotes());
        String deviceCode = data.getDeviceCode();

        String deviceCodeKey = OAuth2DeviceCodeModel.createKey(realm.getId(), deviceCode);
        ActionTokenValueEntity existingDeviceCode = cache.get(deviceCodeKey);

        if (existingDeviceCode == null) {
            return null;
        }

        return OAuth2DeviceCodeModel.fromCache(realm.getId(), deviceCode, existingDeviceCode.getNotes());
    }

    @Override
    public boolean approve(RealmModel realm, ClientModel client, String userCode, String userSessionId) {
        try {
            OAuth2DeviceCodeModel deviceCode = findDeviceCodeByUserCode(realm, userCode);
            if (deviceCode == null) {
                return false;
            }

            OAuth2DeviceCodeModel approved = deviceCode.approve(userSessionId);

            // Update the device code with approved status
            BasicCache<String, ActionTokenValueEntity> cache = codeCache.get();
            cache.replace(approved.serializeKey(), new ActionTokenValueEntity(approved.serializeVerifiedValue()));

            return true;
        } catch (HotRodClientException re) {
            // No need to retry. The hotrod (remoteCache) has some retries in itself in case of some random network error happened.
            // In case of lock conflict, we don't want to retry anyway as there was likely an attempt to remove the code from different place.
            if (logger.isDebugEnabled()) {
                logger.debugf(re, "Failed when verifying device user code %s", userCode);
            }

            return false;
        }
    }

    @Override
    public boolean deny(RealmModel realm, ClientModel client, String userCode) {
        try {
            OAuth2DeviceCodeModel deviceCode = findDeviceCodeByUserCode(realm, userCode);
            if (deviceCode == null) {
                return false;
            }

            OAuth2DeviceCodeModel denied = deviceCode.deny();

            BasicCache<String, ActionTokenValueEntity> cache = codeCache.get();
            cache.replace(denied.serializeKey(), new ActionTokenValueEntity(denied.serializeDeniedValue()));

            return true;
        } catch (HotRodClientException re) {
            // No need to retry. The hotrod (remoteCache) has some retries in itself in case of some random network error happened.
            // In case of lock conflict, we don't want to retry anyway as there was likely an attempt to remove the code from different place.
            if (logger.isDebugEnabled()) {
                logger.debugf(re, "Failed when denying device user code %s", userCode);
            }

            return false;
        }
    }


    @Override
    public boolean remove(OAuth2DeviceCodeModel deviceCode) {
        try {
            BasicCache<String, ActionTokenValueEntity> cache = codeCache.get();
            ActionTokenValueEntity existing = cache.remove(deviceCode.serializeKey());
            return existing == null ? false : true;
        } catch (HotRodClientException re) {
            // No need to retry. The hotrod (remoteCache) has some retries in itself in case of some random network error happened.
            // In case of lock conflict, we don't want to retry anyway as there was likely an attempt to remove the code from different place.
            if (logger.isDebugEnabled()) {
                logger.debugf(re, "Failed when removing device code %s", deviceCode.getDeviceCode());
            }

            return false;
        }
    }
}
