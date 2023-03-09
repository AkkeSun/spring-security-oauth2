package io.security.oauth2.springsecurityoauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

@Configuration
public class Oauth2Config {
    /*
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(){
        return new InMemoryClientRegistrationRepository(keycloakClientRegistration());
    }
    */

    private ClientRegistration keycloakClientRegistration(){
        return ClientRegistration.withRegistrationId("keycloak")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .clientId("keycloak-client-id")
            .clientSecret("6DXU8UzsWxOypCOqbeVjLq0sUaQMculC")
            .redirectUri("http://localhost:8081/login/oauth2/code/keycloak")
            .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
            .scope("openid", "profile", "email", "address", "phone")
            .authorizationUri("http://localhost:8080/realms/oauth2")
            .tokenUri("http://localhost:8080/realms/oauth2/token")
            .userInfoUri("http://localhost:8080/realms/oauth2/userinfo")
            .userNameAttributeName(IdTokenClaimNames.SUB)
            .jwkSetUri("http://localhost:8080/realms/oauth2/certs")
            .clientName("Keycloak")
            .build();
    }
}
