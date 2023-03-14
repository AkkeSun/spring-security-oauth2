package io.security.oauth2.springsecurityoauth2.config;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest.Builder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;


/*
    DefaultOAuth2AuthorizationRequestResolver 를 참고하여 커스터마이징
    registrationId 가 keycloakWithPKCE 인 경우에만 파라미터를 추가하도록 처리
 */
public class CustomOAuth2AuthorizationRequestResolver implements
    OAuth2AuthorizationRequestResolver {

    private final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";
    private DefaultOAuth2AuthorizationRequestResolver defaultResolver;
    private AntPathRequestMatcher antPathRequestMatcher;
    private final Consumer<OAuth2AuthorizationRequest.Builder> DEFAULT_PKCE_APPLIER =
        OAuth2AuthorizationRequestCustomizers.withPkce();

    public CustomOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, String baseUri){
        this.antPathRequestMatcher = new AntPathRequestMatcher(
            baseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
        this.defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, baseUri);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        String registrationId = resolveRegistrationId(request);
        if (registrationId == null) {
            return null;
        }
        if(registrationId.equals("keycloakWithPKCE")){
            return getCustomResolver(request);
        }
        return defaultResolver.resolve(request);
    }

    private OAuth2AuthorizationRequest getCustomResolver(HttpServletRequest request) {
        OAuth2AuthorizationRequest oAuth2AuthorizationRequest = defaultResolver.resolve(request);

        // 추가 파라미터 설정
        Map<String, Object> extraParam = new HashMap<>();
        extraParam.put("customName1", "customValue1");
        extraParam.put("customName2", "customValue2");
        extraParam.put("customName3", "customValue3");

        Builder builder = OAuth2AuthorizationRequest
            .from(oAuth2AuthorizationRequest)  // 디폴트 클래스로 기본값 처리
            .additionalParameters(extraParam); // 추가 파라미터 등록

        DEFAULT_PKCE_APPLIER.accept(builder);
        return builder.build();
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request,
        String clientRegistrationId) {
        return null;
    }

    private String resolveRegistrationId(HttpServletRequest request) {
        if (this.antPathRequestMatcher.matches(request)) {
            return this.antPathRequestMatcher.matcher(request).getVariables()
                .get(REGISTRATION_ID_URI_VARIABLE_NAME);
        }
        return null;
    }
}
