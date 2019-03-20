/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
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

package org.keycloak.authentication.authenticators.browser;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.OAuth2DeviceTokenStoreProvider;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:h2-wada@nri.co.jp">Hiroyuki Wada</a>
 */
public class OAuth2DeviceFormAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {
    @Override
    public void action(AuthenticationFlowContext context) {
        validateUserCode(context);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        Response challengeResponse = challenge(context, null);
        context.challenge(challengeResponse);
    }

    public void validateUserCode(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        if (inputData.containsKey("cancel")) {
            context.resetFlow();
            return;
        }

        UserModel userModel = context.getUser();
        if (!enabledUser(context, userModel)) {
            // error in context is set in enabledUser/isTemporarilyDisabledByBruteForce
            return;
        }

        String userCode = inputData.getFirst(CredentialRepresentation.SECRET);
        if (userCode == null) {
            Response challengeResponse = challenge(context, null);
            context.challenge(challengeResponse);
            return;
        }

        OAuth2DeviceTokenStoreProvider store = context.getSession().getProvider(OAuth2DeviceTokenStoreProvider.class);

        // TODO without client?
        if (!store.verify(context.getRealm(), context.getAuthenticationSession().getClient(), userCode)) {
            context.getEvent().user(userModel)
                    .error(Errors.INVALID_OAUTH2_USER_CODE);
            Response challengeResponse = challenge(context, Messages.INVALID_USER_CODE);
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
            return;
        }

        // Verification OK
        context.getAuthenticationSession().setAuthNote(OIDCLoginProtocol.OAUTH2_DEVICE_VERIFIED_USER_CODE, userCode);

        context.success();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    protected String tempDisabledError() {
        return Messages.INVALID_USER_CODE;
    }

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        return form.createLoginTotp();
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
    }

    @Override
    public void close() {

    }
}
