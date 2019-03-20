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

import java.util.HashMap;
import java.util.Map;

/**
 * @author
 */
public class OAuth2DeviceUserCodeModel {

    private static final String DEVICE_CODE_NOTE = "dc";

    private final String realmId;
    private final String deviceCode;
    private final String userCode;

    public OAuth2DeviceUserCodeModel(RealmModel realm, String deviceCode, String userCode) {
        this.realmId = realm.getId();
        this.deviceCode = deviceCode;
        this.userCode = userCode;
    }

    public static OAuth2DeviceUserCodeModel fromCache(String realmId, String userCode, Map<String, String> data) {
        return new OAuth2DeviceUserCodeModel(realmId, userCode, data);
    }

    private OAuth2DeviceUserCodeModel(String realmId, String userCode, Map<String, String> data) {
        this.realmId = realmId;
        this.userCode = userCode;
        this.deviceCode = data.get(DEVICE_CODE_NOTE);
    }

    public String getDeviceCode() {
        return deviceCode;
    }

    public String getUserCode() {
        return userCode;
    }

    public static String createKey(String realmId, String userCode) {
        return String.format("%s.%s", realmId, userCode);
    }

    public String serializeKey() {
        return createKey(realmId, userCode);
    }

    public Map<String, String> serializeValue() {
        Map<String, String> result = new HashMap<>();
        result.put(DEVICE_CODE_NOTE, deviceCode);
        return result;
    }
}
