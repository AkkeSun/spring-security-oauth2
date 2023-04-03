package io.security.oauth2.springsecurityoauth2.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class ApiController {

    @GetMapping("/api/user")
    public Authentication user(Authentication authentication, @AuthenticationPrincipal OAuth2User oAuth2User) {
        log.info("============ 인가서버에서 가져온 정보 ============");
        log.info(oAuth2User.getName());
        log.info(oAuth2User.getAuthorities().toString());

        log.info("============ 스프링 시큐리티에 저장된 정보 ============");
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        log.info(token.getAuthorizedClientRegistrationId());
        log.info(token.getPrincipal().toString());
        log.info(token.getAuthorities().toString());
        return authentication;
    }

    @GetMapping("/api/oidc") // 요청시 scope 에 openid 가 포함되어야 oidcUser 가 생성된다
    public Authentication oidc(Authentication authentication, @AuthenticationPrincipal OidcUser oidcUser) {
        log.info("============ 인가서버에서 가져온 정보 ============");
        log.info(oidcUser.getName());
        log.info(oidcUser.getAuthorities().toString());

        log.info("============ 스프링 시큐리티에 저장된 정보 ============");
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        log.info(token.getAuthorizedClientRegistrationId());
        log.info(token.getPrincipal().toString());
        log.info(token.getAuthorities().toString());
        return authentication;
    }
}
