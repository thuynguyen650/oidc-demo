package com.example.oauth2.oauth2demo.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.security.Principal;

@RestController
public class DemoController {
    @GetMapping("/")
    public String welcome(@AuthenticationPrincipal OidcUser  principal) {
        return principal.getIdToken().getTokenValue();
    }

    @GetMapping("/oidc-principal")
    public OidcUser getOidcUserPrincipal(@AuthenticationPrincipal OidcUser principal) {
        principal.getIdToken().getTokenValue();
        return principal;
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('APPROLE_Admin')")
    public String welcomeAdmin() {
        return "Hello admin!";
    }

    @GetMapping("isLoggedOn")
    public String isLoggedOn() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated()) {
            if (authentication.getPrincipal() instanceof DefaultOidcUser) {
                DefaultOidcUser oidcUser = (DefaultOidcUser) authentication.getPrincipal();
                return oidcUser.getName();
            }
        }
        return "You haven't logged in yet";
    }

    @GetMapping("/oauth2/callback")
    public String handleCallback(@RequestParam("code") String authorizationCode,
                                 OAuth2AuthenticationToken authenticationToken) {

        OAuth2AuthorizedClient authorizedClient = getAuthorizedClient(authenticationToken);

        // Prepare the request to the token endpoint
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", authorizedClient.getClientRegistration().getClientId());
        body.add("client_secret", authorizedClient.getClientRegistration().getClientSecret());
        body.add("code", authorizationCode);
        body.add("redirect_uri", authorizedClient.getClientRegistration().getRedirectUri());

        // Send the request to the token endpoint
        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(body, headers);
        ResponseEntity<OAuth2AccessTokenResponse> response = restTemplate.postForEntity(
                authorizedClient.getClientRegistration().getProviderDetails().getTokenUri(),
                request, OAuth2AccessTokenResponse.class);

        // Extract the Access Token from the response
        String accessToken = response.getBody().getAccessToken().getTokenValue();

        // Use the Access Token for further authenticated requests

        return "redirect:/";
    }

    @Autowired
    private OAuth2AuthorizedClientService clientService;

    private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authenticationToken) {
        return clientService.loadAuthorizedClient(
                authenticationToken.getAuthorizedClientRegistrationId(),
                authenticationToken.getName());
    }

}

