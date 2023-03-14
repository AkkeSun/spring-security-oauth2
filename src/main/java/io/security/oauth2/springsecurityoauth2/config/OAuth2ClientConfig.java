package io.security.oauth2.springsecurityoauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@EnableWebSecurity
public class OAuth2ClientConfig {

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

        http.authorizeHttpRequests(request ->request
            .antMatchers("/loginPage").permitAll()
            .anyRequest().authenticated());
        http.logout()
            .logoutSuccessHandler(oidcLogoutSuccessHandler())
            .invalidateHttpSession(true)
            .clearAuthentication(true)
            .deleteCookies("JSESSIONID");

        // API 커스텀 설정
        http.oauth2Login(oauth2 -> oauth2
            // 로그인 페이지
            .loginPage("/loginPage")
            // 권한 부여 요청 baseUri (default : /oauth2/authorization)
            .authorizationEndpoint(authorizationEndpointConfig ->
                authorizationEndpointConfig.baseUri("/oauth2/v1/authorization"))
            // 인가 응답 baseUri (application.yml, 인가서버의 정보를 바꿔주어야 오류가 나지 않는다)
            .redirectionEndpoint(redirectionEndpointConfig ->
                redirectionEndpointConfig.baseUri("/login/oauth2/code/*"))
        );
        return http.build();
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler() {
        OidcClientInitiatedLogoutSuccessHandler handler =
            new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        handler.setPostLogoutRedirectUri("http://localhost:8081");
        return handler;
    }
}