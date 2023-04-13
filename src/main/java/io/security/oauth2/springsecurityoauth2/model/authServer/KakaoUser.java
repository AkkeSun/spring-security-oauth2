package io.security.oauth2.springsecurityoauth2.model.authServer;

import io.security.oauth2.springsecurityoauth2.model.OAuth2ProviderUser;
import java.util.Map;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class KakaoUser extends OAuth2ProviderUser {

    public KakaoUser (OAuth2User oAuth2User, ClientRegistration clientRegistration) {
        super(oAuth2User.getAttributes(), oAuth2User, clientRegistration);
    }

    @Override
    public String getId() {
        return (String)((Map<String, Object>) getAttributes().get("kakao_account")).get("email");
    }

    @Override
    public String getUsername() {
        return (String)((Map<String, Object>) getAttributes().get("properties")).get("nickname");
    }

    @Override
    public String getEmail() {
        return (String)((Map<String, Object>) getAttributes().get("kakao_account")).get("email");
    }
}
