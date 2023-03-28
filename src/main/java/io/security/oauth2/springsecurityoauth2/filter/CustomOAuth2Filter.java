package io.security.oauth2.springsecurityoauth2.filter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

public class CustomOAuth2Filter extends AbstractAuthenticationProcessingFilter {

    private static final String DEFAULT_FILTER_PROCESSING_URL = "/refreshToken";
    private final Duration cloakSkew;
    private final Clock clock;
    private final DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager;
    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
    private final OAuth2AuthorizationSuccessHandler successHandler;

    public CustomOAuth2Filter(DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager,
        OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {
        super(DEFAULT_FILTER_PROCESSING_URL);
        this.auth2AuthorizedClientManager = auth2AuthorizedClientManager;
        this.oAuth2AuthorizedClientRepository = oAuth2AuthorizedClientRepository;
        this.successHandler = ((authorizedClient, principal, attributes) -> {
            oAuth2AuthorizedClientRepository
                .saveAuthorizedClient(authorizedClient, principal,
                    (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                    (HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
        });
        this.clock = Clock.systemUTC();
        this.cloakSkew = Duration.ofSeconds(3600);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
        HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 컨트롤러에서 직접 처리하는 경우, 해당 구문은 필요 없습니다.
        // SecurityContextHolder.getContext().getAuthentication() 가 알아서 anonymousToken 을 만들어주기 때문입니다
        // 이는 커스텀 필터 뒤에서 실행되는 작업이므로 필터기반 로그인 처리시에는 직접 해주어야합니다.
        if(authentication == null) {
            authentication = new AnonymousAuthenticationToken("anonymous", "anonymousUser",
                AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        }

        OAuth2AuthorizeRequest oAuth2AuthorizeRequest =
            OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak")
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        OAuth2AuthorizedClient authorize = auth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
        System.out.println(authorize.getAccessToken().getTokenValue());

        if (authorize != null && hasTokenExpired(authorize.getAccessToken()) && authorize.getRefreshToken() != null) {
            ClientRegistration clientRegistration = ClientRegistration
                .withClientRegistration(authorize.getClientRegistration())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();
            authorize = new OAuth2AuthorizedClient(
                clientRegistration, authorize.getPrincipalName(), authorize.getAccessToken(), authorize.getRefreshToken());
            oAuth2AuthorizeRequest = OAuth2AuthorizeRequest
                .withAuthorizedClient(authorize)
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();
            authorize = auth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
            System.out.println(authorize.getAccessToken().getTokenValue());
        }

        if (authorize != null) {
            OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
            ClientRegistration clientRegistration = authorize.getClientRegistration();
            OAuth2AccessToken accessToken = authorize.getAccessToken();
            OAuth2UserRequest userRequest = new OAuth2UserRequest(clientRegistration, accessToken);
            OAuth2User oAuth2User = oAuth2UserService.loadUser(userRequest);
            OAuth2AuthenticationToken oAuth2AuthenticationToken =
                new OAuth2AuthenticationToken(oAuth2User, oAuth2User.getAuthorities(), clientRegistration.getRegistrationId());
            SecurityContextHolder.getContext().setAuthentication(oAuth2AuthenticationToken);
            this.successHandler.onAuthorizationSuccess(authorize, oAuth2AuthenticationToken, createAttributes(request, response));
            return oAuth2AuthenticationToken;
        }
        return null;
    }

    private boolean hasTokenExpired(OAuth2Token accessToken) {
        return this.clock.instant().isAfter(accessToken.getExpiresAt().minus(this.cloakSkew));
    }

    private Map<String, Object> createAttributes(HttpServletRequest request, HttpServletResponse response) {
        Map<String, Object> attributes = new HashMap<>();
        attributes.put(HttpServletRequest.class.getName(), request);
        attributes.put(HttpServletResponse.class.getName(), response);
        return attributes;
    }
}
