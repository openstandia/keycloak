/*
 * Copyright 2019 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.migration.migrators;

import org.keycloak.migration.ModelVersion;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.representations.idm.RealmRepresentation;

import java.util.List;

/**
 * @author <a href="mailto:h2-wada@nri.co.jp">Hiroyuki Wada</a>
 */
public class MigrateTo6_0_0 implements Migration {
    public static final ModelVersion VERSION = new ModelVersion("6.0.0");

    @Override
    public ModelVersion getVersion() {
        return VERSION;
    }

    public void setupOAuth2DeviceService(RealmModel realm) {
        ClientModel client = realm.getClientByClientId(Constants.OAUTH2_DEVICE_SERVICE_CLIENT_ID);
        if (client == null) {
            client = KeycloakModelUtils.createClient(realm, Constants.OAUTH2_DEVICE_SERVICE_CLIENT_ID);
            client.setEnabled(true);
            client.setName("${client_" + Constants.OAUTH2_DEVICE_SERVICE_CLIENT_ID + "}");
            client.setFullScopeAllowed(false);
            client.setStandardFlowEnabled(false);
            client.setImplicitFlowEnabled(false);
            client.setServiceAccountsEnabled(false);
            client.setDirectAccessGrantsEnabled(false);
            client.setOAuth2DeviceGrantEnabled(true);
            client.setProtocol("openid-connect");
        }
    }

    public void migrate(KeycloakSession session) {
        List<RealmModel> realms = session.realms().getRealms();
        for (RealmModel realm : realms) {
            setupOAuth2DeviceService(realm);
        }
    }

    @Override
    public void migrateImport(KeycloakSession session, RealmModel realm, RealmRepresentation rep, boolean skipUserDependent) {
        setupOAuth2DeviceService(realm);
    }
}
