package org.kkeyser.keycloak.auth.iprange;

import lombok.extern.jbosslog.JBossLog;
import org.keycloak.Config;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

@JBossLog
public class IpRangeConditionFactory implements ConditionalAuthenticatorFactory {
    public static final String CONDITION_DEFAULT_ALLOW = "default-allow";
    public static final String CONDITION_EXCEPTIONS_LIST = "exceptions-list";
    public static final String CONDITION_DEBUG_ALLOW = "debug-allow";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();
    static {
        ProviderConfigProperty exceptionsList = new ProviderConfigProperty();
        exceptionsList.setType(ProviderConfigProperty.MULTIVALUED_STRING_TYPE);
        exceptionsList.setName(CONDITION_EXCEPTIONS_LIST);
        exceptionsList.setLabel("Exceptions");
        exceptionsList.setHelpText("The list of exceptions in CIDR or IP-range format.\nIf client's IP address will match any of these ranges, condition will return TRUE (if 'Allow by default' is OFF) or FALSE (if 'Allow by default is ON')");
        configProperties.add(exceptionsList);

        ProviderConfigProperty defaultAction = new ProviderConfigProperty();
        defaultAction.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        defaultAction.setName(CONDITION_DEFAULT_ALLOW);
        defaultAction.setLabel("Allow all by default");
        defaultAction.setHelpText("The default value will be returned if client's IP isn't matched by any exceptions listed above. ON - return TRUE, OFF - return FALSE");
        configProperties.add(defaultAction);

        ProviderConfigProperty debugAllowed = new ProviderConfigProperty();
        debugAllowed.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        debugAllowed.setName(CONDITION_DEBUG_ALLOW);
        debugAllowed.setLabel("Debug");
        debugAllowed.setHelpText("If turned ON, some debug data will be written in the log file");
        configProperties.add(debugAllowed);
    }

    private static final IpRangeCondition INSTANCE = new IpRangeCondition();

    @Override
    public ConditionalAuthenticator getSingleton() {
        return INSTANCE;
    }

    @Override
    public String getDisplayType() {
        return "Condition - IP range";
    }

    @Override
    public String getReferenceCategory() {
        return "condition";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    private static final Requirement[] REQUIREMENT_CHOICES = {
        AuthenticationExecutionModel.Requirement.REQUIRED, AuthenticationExecutionModel.Requirement.DISABLED
    };

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Flow is executed only if client's IP address meets the given conditions";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public void init(Config.Scope config) {
        // NOOP
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // NOOP
    }

    @Override
    public void close() {
        // NOOP
    }

    @Override
    public String getId() {
        return IpRangeCondition.ID;
    }
}
