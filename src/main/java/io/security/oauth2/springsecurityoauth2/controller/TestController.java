package io.security.oauth2.springsecurityoauth2.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
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

}