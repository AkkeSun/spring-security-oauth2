package io.security.oauth2.springsecurityoauth2.controller;


import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index(Model model, Authentication authentication,
        @AuthenticationPrincipal OAuth2User oAuth2User){
        model.addAttribute("user", getUsername(authentication, oAuth2User));
        return "index";
    }

    private String getUsername(Authentication authentication, OAuth2User oAuth2User){
        OAuth2AuthenticationToken authenticationToken = (OAuth2AuthenticationToken)authentication;
        if(authenticationToken != null){
            // 인가서버에서 가져온 사용자 정보
            Map<String, Object> attributes = oAuth2User.getAttributes();
            if(authenticationToken.getAuthorizedClientRegistrationId().equals("naver")){
                Map<String, Object> response = (Map)attributes.get("response");
                return (String)response.get("name");
            }
            return (String)attributes.get("name");
        }
        return "";
    }

}