package org.kkeyser.keycloak.auth.iprange;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.common.ClientConnection;
import inet.ipaddr.IPAddressString;
import inet.ipaddr.AddressStringException;

import java.util.Map;

@JBossLog
public class IpRangeCondition implements ConditionalAuthenticator {

    public static final String ID = "custom-ip-range-condition";

    @Override
    public boolean matchCondition(AuthenticationFlowContext context) {
        ClientConnection clientConnection = context.getConnection();

        AuthenticatorConfigModel authenticatorConfig = context.getAuthenticatorConfig();
        if (authenticatorConfig == null) {
            return false;
        }
        Map<String, String> config = authenticatorConfig.getConfig();
        if (config == null) {
            return false;
        }

        boolean debug = Boolean.parseBoolean(config.getOrDefault(IpRangeConditionFactory.CONDITION_DEBUG_ALLOW, "false"));
        if (debug) {
          log.info("matchCondition(), getRemoteAddr(): " + clientConnection.getRemoteAddr());
          log.info("matchCondition(), config(" + IpRangeConditionFactory.CONDITION_DEFAULT_ALLOW + "): " + config.get(IpRangeConditionFactory.CONDITION_DEFAULT_ALLOW));
          log.info("matchCondition(), config(" + IpRangeConditionFactory.CONDITION_EXCEPTIONS_LIST + "): " + config.get(IpRangeConditionFactory.CONDITION_EXCEPTIONS_LIST));
        }

        boolean defaultAllow = Boolean.parseBoolean(config.getOrDefault(IpRangeConditionFactory.CONDITION_DEFAULT_ALLOW, "false"));

        IPAddressString remoteAddr = new IPAddressString(clientConnection.getRemoteAddr());
        String exceptionsList = config.get(IpRangeConditionFactory.CONDITION_EXCEPTIONS_LIST);
        if (exceptionsList != null) {
          String[] exceptions = exceptionsList.split("##");
          for (String exception : exceptions) {
            IPAddressString exceptionRange = new IPAddressString(exception);
            if (exceptionRange.contains(remoteAddr)) {
              if (debug) {
                log.info("matchCondition(): " + exceptionRange + " contains " + remoteAddr + ", returing " + !defaultAllow);
              }
              return !defaultAllow;
            } else {
              if (debug) {
                log.info("matchCondition: " + exceptionRange + " do not contains " + remoteAddr);
              }
            }
          }
        }
        if (debug) {
          log.info("matchCondition: return default " + defaultAllow);
        }
        return defaultAllow;
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // NOOP
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }
}
