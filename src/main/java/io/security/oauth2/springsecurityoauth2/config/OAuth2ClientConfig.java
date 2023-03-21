package io.security.oauth2.springsecurityoauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;


@EnableWebSecurity
public class OAuth2ClientConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(request ->request
            .antMatchers("/", "/oauth2Login").permitAll()
            .anyRequest().authenticated());
        http.oauth2Client(Customizer.withDefaults());
        return http.build();
    }
}