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

package org.keycloak.protocol.oidc.endpoints;

import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.common.util.Base64Url;
import org.keycloak.common.util.RandomString;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequest;
import org.keycloak.protocol.oidc.endpoints.request.AuthorizationEndpointRequestParserProcessor;
import org.keycloak.protocol.oidc.utils.*;
import org.keycloak.representations.OAuth2DeviceAuthorizationResponse;
import org.keycloak.services.ErrorPageException;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.Urls;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.managers.AuthenticationSessionManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.RealmsResource;
import org.keycloak.services.util.CacheControlUtil;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.keycloak.util.TokenUtil;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import java.security.SecureRandom;

import static org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX;

/**
 * @author <a href="mailto:h2-wada@nri.co.jp">Hiroyuki Wada</a>
 */
public class OAuth2DeviceAuthorizationEndpoint extends AuthorizationEndpointBase {

    private static final Logger logger = Logger.getLogger(OAuth2DeviceAuthorizationEndpoint.class);

    public static final String OAUTH2_DEVICE_AUTH_TYPE = "oauth2_device";

    private enum Action {
        OAUTH2_DEVICE_AUTH, OAUTH2_DEVICE_VERIFY_USER_CODE
    }

    private ClientModel client;
    private AuthenticationSessionModel authenticationSession;

    private Action action;

    private AuthorizationEndpointRequest request;

    public OAuth2DeviceAuthorizationEndpoint(RealmModel realm, EventBuilder event) {
        super(realm, event);
        event.event(EventType.OAUTH2_DEVICE_AUTH);
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response buildPost() {
        logger.trace("Processing @POST request");
        action = Action.OAUTH2_DEVICE_AUTH;
        return process(httpRequest.getDecodedFormParameters());
    }

    private Response process(MultivaluedMap<String, String> params) {
        String clientId = params.getFirst(OIDCLoginProtocol.CLIENT_ID_PARAM);

        checkSsl();
        checkRealm();
        checkClient(clientId);

        request = AuthorizationEndpointRequestParserProcessor.parseRequest(event, session, client, params);

        if (!TokenUtil.isOIDCRequest(request.getScope())) {
            ServicesLogger.LOGGER.oidcScopeMissing();
        }

        authenticationSession = createAuthenticationSession(client, request.getState());
        updateAuthenticationSession();

        // So back button doesn't work
        CacheControlUtil.noBackButtonCacheControlHeader();
        switch (action) {
            case OAUTH2_DEVICE_AUTH:
                return buildDeviceAuthorizationResponse();
        }

        throw new RuntimeException("Unknown action " + action);
    }

    public Response buildDeviceAuthorizationResponse() {
        if (!client.isOAuth2DeviceGrantEnabled()) {
            // TODO JSON Response
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.OAUTH2_DEVICE_GRANT_DISABLED);
        }

        int expiresIn = realm.getOAuth2DeviceCodeLifespan();
        int interval = realm.getOAuth2DevicePollingInterval();

        OAuth2DeviceCodeModel deviceCode = OAuth2DeviceCodeModel.create(realm, client,
                Base64Url.encode(KeycloakModelUtils.generateSecret()), request.getScope(), request.getNonce());

        // TODO Configure the length
        String secret = new RandomString(10, new SecureRandom(), RandomString.upper).nextString();
        OAuth2DeviceUserCodeModel userCode = new OAuth2DeviceUserCodeModel(realm,
                deviceCode.getDeviceCode(),
                secret);
        String displaySecret = new StringBuilder(secret).insert(5, "-").toString();

        // To inform "expired_token" to the client, the lifespan of the cache provider is longer than device code
        int lifespanSeconds = expiresIn + interval + 10;

        OAuth2DeviceTokenStoreProvider store = session.getProvider(OAuth2DeviceTokenStoreProvider.class);
        store.create(deviceCode, userCode, lifespanSeconds);

        try {
            String deviceUrl = RealmsResource.oauth2DeviceVerificationUrl(session.getContext().getUri()).build(realm.getName()).toString();

            OAuth2DeviceAuthorizationResponse response = new OAuth2DeviceAuthorizationResponse();
            response.setDeviceCode(deviceCode.getDeviceCode());
            response.setUserCode(displaySecret);
            response.setExpiresIn(expiresIn);
            response.setInterval(interval);
            response.setVerificationUri(deviceUrl);
            response.setVerificationUriComplete(deviceUrl + "?user_code=" + response.getUserCode());

            return Response.ok(JsonSerialization.writeValueAsBytes(response)).type(MediaType.APPLICATION_JSON_TYPE).build();
        } catch (Exception e) {
            throw new RuntimeException("Error creating device authorization response.", e);
        }
    }

    private void checkClient(String clientId) {
        if (clientId == null) {
            event.error(Errors.INVALID_REQUEST);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.MISSING_PARAMETER, OIDCLoginProtocol.CLIENT_ID_PARAM);
        }

        event.client(clientId);

        client = realm.getClientByClientId(clientId);
        if (client == null) {
            event.error(Errors.CLIENT_NOT_FOUND);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.CLIENT_NOT_FOUND);
        }

        if (!client.isEnabled()) {
            event.error(Errors.CLIENT_DISABLED);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.CLIENT_DISABLED);
        }

        if (!client.isOAuth2DeviceGrantEnabled()) {
            event.error(Errors.NOT_ALLOWED);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, Messages.OAUTH2_DEVICE_GRANT_DISABLED);
        }

        if (client.isBearerOnly()) {
            event.error(Errors.NOT_ALLOWED);
            throw new ErrorPageException(session, authenticationSession, Response.Status.FORBIDDEN, Messages.BEARER_ONLY);
        }

        String protocol = client.getProtocol();
        if (protocol == null) {
            logger.warnf("Client '%s' doesn't have protocol set. Fallback to openid-connect. Please fix client configuration", clientId);
            protocol = OIDCLoginProtocol.LOGIN_PROTOCOL;
        }
        if (!protocol.equals(OIDCLoginProtocol.LOGIN_PROTOCOL)) {
            event.error(Errors.INVALID_CLIENT);
            throw new ErrorPageException(session, authenticationSession, Response.Status.BAD_REQUEST, "Wrong client protocol.");
        }

        // https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-3.1
        // The spec says "The client authentication requirements of Section 3.2.1 of [RFC6749]
        // apply to requests on this endpoint".
        if (client.isOAuth2DeviceGrantEnabled() && action == Action.OAUTH2_DEVICE_AUTH) {
            AuthorizeClientUtil.ClientAuthResult clientAuth = AuthorizeClientUtil.authorizeClient(session, event);
            client = clientAuth.getClient();
        }

        session.getContext().setClient(client);
    }

    private void updateAuthenticationSession() {
        authenticationSession.setProtocol(OIDCLoginProtocol.LOGIN_PROTOCOL);
        authenticationSession.setAction(AuthenticationSessionModel.Action.AUTHENTICATE.name());
        authenticationSession.setClientNote(OIDCLoginProtocol.ISSUER, Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName()));

        if (request.getNonce() != null) authenticationSession.setClientNote(OIDCLoginProtocol.NONCE_PARAM, request.getNonce());
        if (request.getMaxAge() != null) authenticationSession.setClientNote(OIDCLoginProtocol.MAX_AGE_PARAM, String.valueOf(request.getMaxAge()));
        if (request.getScope() != null) authenticationSession.setClientNote(OIDCLoginProtocol.SCOPE_PARAM, request.getScope());
        if (request.getLoginHint() != null) authenticationSession.setClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM, request.getLoginHint());
        if (request.getPrompt() != null) authenticationSession.setClientNote(OIDCLoginProtocol.PROMPT_PARAM, request.getPrompt());
        if (request.getIdpHint() != null) authenticationSession.setClientNote(AdapterConstants.KC_IDP_HINT, request.getIdpHint());
        if (request.getClaims()!= null) authenticationSession.setClientNote(OIDCLoginProtocol.CLAIMS_PARAM, request.getClaims());
        if (request.getAcr() != null) authenticationSession.setClientNote(OIDCLoginProtocol.ACR_PARAM, request.getAcr());
        if (request.getDisplay() != null) authenticationSession.setAuthNote(OAuth2Constants.DISPLAY, request.getDisplay());

        if (request.getAdditionalReqParams() != null) {
            for (String paramName : request.getAdditionalReqParams().keySet()) {
                authenticationSession.setClientNote(LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + paramName, request.getAdditionalReqParams().get(paramName));
            }
        }
    }

    public Response buildVerificationResponse() {
        this.event.event(EventType.LOGIN);
        action = Action.OAUTH2_DEVICE_VERIFY_USER_CODE;

        String clientId = Constants.OAUTH2_DEVICE_SERVICE_CLIENT_ID;

        checkSsl();
        checkRealm();
        checkClient(clientId);

        request = AuthorizationEndpointRequestParserProcessor.parseRequest(event, session, client, session.getContext().getUri().getQueryParameters());

        authenticationSession = createAuthenticationSession(client, request.getState());
        updateAuthenticationSession();

        // So back button doesn't work
        CacheControlUtil.noBackButtonCacheControlHeader();

        authenticationSession.setAuthNote(Details.AUTH_TYPE, OAUTH2_DEVICE_AUTH_TYPE);

        return handleBrowserAuthenticationRequest(authenticationSession, new OIDCLoginProtocol(session, realm, session.getContext().getUri(), headers, event), false, false);
    }

    public AuthenticationSessionModel attachDeviceClient(AuthenticationSessionModel preAuthSession, OAuth2DeviceCodeModel deviceCode) {
        authenticationSession = preAuthSession;

        checkClient(deviceCode.getClientId());

        request = AuthorizationEndpointRequestParserProcessor.parseRequest(event, session, client, deviceCode.getParams());

        RootAuthenticationSessionModel rootAuthSession = new AuthenticationSessionManager(session).createAuthenticationSession(realm, true);
        authenticationSession = rootAuthSession.createAuthenticationSession(client);

        logger.debugf("Root authentication session with ID '%s' exists. Client is '%s' . Created new authentication session with tab ID: %s",
                rootAuthSession.getId(), client.getClientId(), authenticationSession.getTabId());

        // Copy from pre-authentication session
        authenticationSession.setAuthenticatedUser(preAuthSession.getAuthenticatedUser());
        authenticationSession.setClientNote(OAuth2Constants.SCOPE, preAuthSession.getClientNote(OAuth2Constants.SCOPE));
        authenticationSession.setAuthNote(Details.AUTH_TYPE, preAuthSession.getAuthNote(Details.AUTH_TYPE));
        authenticationSession.setAuthenticatedUser(preAuthSession.getAuthenticatedUser());

        updateAuthenticationSession();

        AuthenticationManager.setClientScopesInSession(authenticationSession);

        return authenticationSession;
    }
}
