package io.security.oauth2.springsecurityoauth2.service;

import io.security.oauth2.springsecurityoauth2.model.ProviderUser;
import io.security.oauth2.springsecurityoauth2.model.User;
import io.security.oauth2.springsecurityoauth2.model.authServer.GoogleUser;
import io.security.oauth2.springsecurityoauth2.model.authServer.KakaoUser;
import io.security.oauth2.springsecurityoauth2.model.authServer.KeycloakUser;
import io.security.oauth2.springsecurityoauth2.model.authServer.NaverUser;
import io.security.oauth2.springsecurityoauth2.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public abstract class AbstractOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    public void register(ProviderUser providerUser, OAuth2UserRequest userRequest){
        User user = userRepository.findByUsername(providerUser.getUsername());
        if(user == null){
            ClientRegistration clientRegistration = userRequest.getClientRegistration();
            user = User.builder().registrationId(clientRegistration.getRegistrationId())
                .id(providerUser.getId())
                .username(providerUser.getUsername())
                .password(providerUser.getPassword())
                .authorities(providerUser.getAuthorities())
                .provider(providerUser.getProvider())
                .email(providerUser.getEmail())
                .build();
            userRepository.save(user);
        }else{
            System.out.println("userRequest = " + userRequest);
        }
    }

    public ProviderUser providerUser(ClientRegistration clientRegistration, OAuth2User oAuth2User){

        String registrationId = clientRegistration.getRegistrationId();
        if(registrationId.equals("keycloak")){
            return new KeycloakUser(oAuth2User,clientRegistration);
        } else if(registrationId.equals("google")){
            return new GoogleUser(oAuth2User,clientRegistration);
        } else if(registrationId.equals("naver")){
            return new NaverUser(oAuth2User,clientRegistration);
        } else if(registrationId.equals("kakao")){
            return new KakaoUser(oAuth2User, clientRegistration);
        }
        return null;
    }
}
