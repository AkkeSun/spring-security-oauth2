package io.security.oauth2.springsecurityoauth2.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
public class TestController {

    private final ClientRegistrationRepository clientRegistrationRepository;

    @GetMapping
    public String test(){
        ClientRegistration keycloak =
            clientRegistrationRepository.findByRegistrationId("keycloak");
        log.info(keycloak.getClientId());
        return "success";
    }

    @GetMapping("/user")
    public OAuth2User getUser(Authentication authentication){
        OAuth2AuthenticationToken authenticationToken1 = (OAuth2AuthenticationToken) authentication;
        return authenticationToken1.getPrincipal();
    }

    @GetMapping("/oauth2User")
    public OAuth2User getOauth2User(@AuthenticationPrincipal OAuth2User oAuth2User){
        return oAuth2User;
    }

}