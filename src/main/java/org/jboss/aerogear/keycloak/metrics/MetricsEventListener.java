package org.jboss.aerogear.keycloak.metrics;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.Details;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.RealmModel;

import java.util.Arrays;
import java.util.List;
import java.util.Collections;
import java.util.Map;

public class MetricsEventListener implements EventListenerProvider {

    public final static String ID = "metrics-listener";
    private final static String PROVIDER_KEYCLOAK_OPENID = "keycloak";

    private final static Logger logger = Logger.getLogger(MetricsEventListener.class);
    private final RealmProvider realmProvider;

    private static final List<String> EXCLUDED_REALMS = getExcludedRealms();
    private static final List<String> EXCLUDED_PROVIDERS = getExcludedProviders();

    public MetricsEventListener(RealmProvider realmProvider) {
        this.realmProvider = realmProvider;
    }

    private static List<String> getExcludedRealms() {
        String excludedRealms = System.getenv("METRICS_EXCLUDED_REALMS");
        return excludedRealms != null ? Arrays.asList(excludedRealms.split(",")) : Collections.emptyList();
    }

    private static List<String> getExcludedProviders() {
        String excludedProviders = System.getenv("METRICS_EXCLUDED_PROVIDERS");
        return excludedProviders != null ? Arrays.asList(excludedProviders.split(",")) : Collections.emptyList();
    }

    private boolean isRealmExcluded(String realmName) {
        return EXCLUDED_REALMS.contains(realmName);
    }

    private boolean isProviderExcluded(String provider) {
        return EXCLUDED_PROVIDERS.contains(provider);
    }

    private String getRealmName(String realmId) {
        RealmModel realm = realmProvider.getRealm(realmId);
        return realm != null ? realm.getName() : null;
    }

    private String getIdentityProvider(Event event) {
        String identityProvider = null;
        if (event.getDetails() != null) {
            identityProvider = event.getDetails().get("identity_provider");
        }
        if (identityProvider == null) {
            identityProvider = PROVIDER_KEYCLOAK_OPENID;
        }
        return identityProvider;
    }

    @Override
    public void onEvent(Event event) {
        logEventDetails(event);

        final String realmName = getRealmName(event.getRealmId());
        final String provider = getIdentityProvider(event);

        logger.debugf("Processing event for realm: %s, provider: %s", realmName, provider);

        if (isRealmExcluded(realmName) || isProviderExcluded(provider)) {
            logger.debugf("Event excluded for realm: %s, provider: %s", realmName, provider);
            return;
        }

        switch (event.getType()) {
            case LOGIN:
                PrometheusExporter.instance().recordLogin(event, realmProvider);
                break;
            case CLIENT_LOGIN:
                PrometheusExporter.instance().recordClientLogin(event, realmProvider);
                break;
            case REGISTER:
                PrometheusExporter.instance().recordRegistration(event, realmProvider);
                break;
            case REFRESH_TOKEN:
                PrometheusExporter.instance().recordRefreshToken(event, realmProvider);
                break;
            case CODE_TO_TOKEN:
                PrometheusExporter.instance().recordCodeToToken(event, realmProvider);
                break;
            case REGISTER_ERROR:
                PrometheusExporter.instance().recordRegistrationError(event, realmProvider);
                break;
            case LOGIN_ERROR:
                PrometheusExporter.instance().recordLoginError(event, realmProvider);
                break;
            case CLIENT_LOGIN_ERROR:
                PrometheusExporter.instance().recordClientLoginError(event, realmProvider);
                break;
            case REFRESH_TOKEN_ERROR:
                PrometheusExporter.instance().recordRefreshTokenError(event, realmProvider);
                break;
            case CODE_TO_TOKEN_ERROR:
                PrometheusExporter.instance().recordCodeToTokenError(event, realmProvider);
                break;
            default:
                PrometheusExporter.instance().recordGenericEvent(event, realmProvider);
        }
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {
        logAdminEventDetails(event);

        PrometheusExporter.instance().recordGenericAdminEvent(event, realmProvider);
    }

    private void logEventDetails(Event event) {
        logger.debugf("Received user event of type %s in realm %s",
                event.getType().name(),
                event.getRealmId());
    }

    private void logAdminEventDetails(AdminEvent event) {
        logger.debugf("Received admin event of type %s (%s) in realm %s",
                event.getOperationType().name(),
                event.getResourceType().name(),
                event.getRealmId());
    }

    @Override
    public void close() {
        // unused
    }
}
