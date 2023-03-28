package io.security.oauth2.springsecurityoauth2.controller;

import java.time.Clock;
import java.time.Duration;
import java.util.Set;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.aop.support.AopUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class Oauth2ClientController {

    private final DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager;

    @GetMapping("/oauth2Login")
    public String oauth2Login(Model model, HttpServletRequest request, HttpServletResponse response){

        // 인증받지 않은 Anonymous Token
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        OAuth2AuthorizeRequest oAuth2AuthorizeRequest =
            OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak")
                .principal(authentication) // 인증객채 등록
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        // 인가받은 클라이언트
        OAuth2AuthorizedClient authorize = auth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
        if (authorize != null) {

            // =========== 인증 처리 ============
            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
            ClientRegistration clientRegistration = authorize.getClientRegistration();
            OAuth2AccessToken accessToken = authorize.getAccessToken();
            OAuth2UserRequest userRequest = new OAuth2UserRequest(clientRegistration, accessToken);
            OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);

            // 인증객채 생성
            OAuth2AuthenticationToken oAuth2AuthenticationToken =
                new OAuth2AuthenticationToken(oAuth2User, oAuth2User.getAuthorities(), clientRegistration.getRegistrationId());

            /* ROLE 커스텀하여 인증객채 생성 */
            /*
            SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
            authorityMapper.setPrefix("SYSTEM_");
            Set<GrantedAuthority> grantedAuthorities = authorityMapper.mapAuthorities(oAuth2User.getAuthorities());
            OAuth2AuthenticationToken oAuth2AuthenticationToken =
                new OAuth2AuthenticationToken(oAuth2User, grantedAuthorities, clientRegistration.getRegistrationId());
             */

            // 인증객채를 Client SecurityContextHolder 에 저장
            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);
            System.out.println(oAuth2AuthenticationToken);
        }

        return "redirect:/";
    }


    @GetMapping("/clientCredentials")
    public String clientCredentialsLogin(HttpServletRequest request, HttpServletResponse response){

        // 인증받지 않은 Anonymous Token
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        OAuth2AuthorizeRequest oAuth2AuthorizeRequest =
            OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak")
                .principal(authentication) // 인증객채 등록
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        // 인가받은 클라이언트 (Client Credentials 은 인가받는게 목적이기 때문에 사용자 인증을 받을 필요가 없으므로 여기서 끝)
        OAuth2AuthorizedClient authorize = auth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
        //System.out.println(authorize.getAccessToken());
        return "redirect:/";
    }

    @GetMapping("/logout")
    public String logout(Authentication authentication, HttpServletRequest request, HttpServletResponse response){
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);
        return "redirect:/";
    }

    @GetMapping("/")
    public String index (){
        return "index";
    }

}
