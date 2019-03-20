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

package org.keycloak.models;

import org.keycloak.provider.Provider;

import java.util.Map;

/**
 * Provides cache for OAuth2 device grant tokens.
 *
 * @author <a href="mailto:h2-wada@nri.co.jp">Hiroyuki Wada</a>
 */
public interface OAuth2DeviceTokenStoreProvider extends Provider {

    /**
     * Stores the given device code and user code
     *
     * @param deviceCode
     * @param userCode
     */
    void create(OAuth2DeviceCodeModel deviceCode, OAuth2DeviceUserCodeModel userCode, int lifespanSeconds);

    OAuth2DeviceCodeModel get(RealmModel realm, ClientModel client, String deviceCode);

    boolean checkPollingInterval(OAuth2DeviceCodeModel deviceCode, int nextIntervalSeconds);

    OAuth2DeviceCodeModel get(RealmModel realm, String userCode);

    boolean verify(RealmModel realm, ClientModel client, String userCode);

    boolean approve(RealmModel realm, ClientModel client, String userCode, String userSessionId);

    boolean deny(RealmModel realm, ClientModel client, String userCode);

    boolean remove(OAuth2DeviceCodeModel deviceCode);
}
