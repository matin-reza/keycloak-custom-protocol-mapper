package com.art.nobino.keycloak.spi.validIP;

import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class CustomProtocolMapper extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    public static final String PROVIDER_ID = "ip-role-mapper";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    static final String LOWER_BOUND = "lowerBound";
    static final String UPPER_BOUND = "upperBound";
    static final String IP_LIST = "ip-list";

    static {
        configProperties.add(new ProviderConfigProperty(LOWER_BOUND, "Lower Bound", "Lower bound of lucky number.", ProviderConfigProperty.STRING_TYPE, 1));
        configProperties.add(new ProviderConfigProperty(UPPER_BOUND, "Upper Bound", "Upper bound of lucky number.", ProviderConfigProperty.STRING_TYPE, 100));
        configProperties.add(new ProviderConfigProperty(IP_LIST, "IP_LIST", "The list of valid ips", ProviderConfigProperty.STRING_TYPE, "127.0.0.1"));

        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, CustomProtocolMapper.class);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayCategory() {
        return TOKEN_MAPPER_CATEGORY;
    }

    @Override
    public String getDisplayType() {
        return "ip validation";
    }

    @Override
    public String getHelpText() {
        return "Map the related roles to the claim if the ip will be valid.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        super.setClaim(token, mappingModel, userSession, keycloakSession, clientSessionCtx);
        String ips = mappingModel.getConfig().get(IP_LIST);
        String clientIp = userSession.getIpAddress();  // Get the client IP address
        if (ips != null && !ips.equals("")) {
            String[] ipss = ips.split(",");
            for (int i = 0; i < ipss.length; i++) {
                if (clientIp.equals(ipss[i])) {
                    List<RoleModel> realmRoles = userSession.getUser().getRealmRoleMappingsStream().toList();
                    List<String> roles = realmRoles.stream()
                            .map(RoleModel::getName)
                            .collect(Collectors.toList());
                    // Add the additional string
                    String additionalString = "custom_string_value";
                    roles.add(additionalString);

                    // Include the roles and the client IP address in the token
                    Map<String, Object> customClaims = new HashMap<>();
                    customClaims.put("roles", roles);

                    OIDCAttributeMapperHelper.mapClaim(token, mappingModel, customClaims);
                    break;
                }
            }
        }
    }
}