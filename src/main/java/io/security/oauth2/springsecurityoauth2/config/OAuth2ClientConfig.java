package io.security.oauth2.springsecurityoauth2.config;

import io.security.oauth2.springsecurityoauth2.service.CustomOAuth2UserService;
import io.security.oauth2.springsecurityoauth2.service.CustomOidcUserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;


@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2ClientConfig {

    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomOidcUserService customOidcUserService;

    // 정적 파일 처리
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return (web -> web.ignoring().antMatchers(
            "/static/js/**", "/static/css/**", "static/scss/**"
        ));
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.authorizeRequests(request ->request
            .antMatchers("/api/user").access("hasAnyRole('SCOPE_profile','SCOPE_email')")
            .antMatchers("/api/oidc").access("hasAnyRole('SCOPE_openid')")
            .antMatchers("/").permitAll()
            .anyRequest().authenticated());
        http.logout()
            .logoutSuccessUrl("/");
        http.oauth2Login(oauth2 -> oauth2.userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig
                .userService(customOAuth2UserService)
                .oidcUserService(customOidcUserService)));
        return http.build();
    }

}