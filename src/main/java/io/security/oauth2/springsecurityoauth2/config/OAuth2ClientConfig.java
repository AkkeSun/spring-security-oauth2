package io.security.oauth2.springsecurityoauth2.config;

import io.security.oauth2.springsecurityoauth2.filter.CustomOAuth2Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@EnableWebSecurity
@RequiredArgsConstructor
public class OAuth2ClientConfig {

    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
    private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(request ->request
            .antMatchers("/", "/oauth2Login", "/clientCredentials", "/refreshToken", "/v2/refreshToken").permitAll()
            .anyRequest().authenticated());
        http.oauth2Client(Customizer.withDefaults());
        http.addFilterBefore(customOAuth2Filter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    private CustomOAuth2Filter customOAuth2Filter () {
        CustomOAuth2Filter oAuth2Filter =
            new CustomOAuth2Filter(oAuth2AuthorizedClientManager, oAuth2AuthorizedClientRepository);
        oAuth2Filter.setAuthenticationSuccessHandler(((request, response, authentication) -> {
            response.sendRedirect("/");
        }));
        return oAuth2Filter;
    }
}