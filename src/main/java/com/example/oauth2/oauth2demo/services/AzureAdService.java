package com.example.oauth2.oauth2demo.services;

import com.example.oauth2.oauth2demo.utils.AccessTokenRetriever;
import com.microsoft.graph.models.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class AzureAdService {
    private final AccessTokenRetriever accessTokenRetriever;

    public AzureAdService(
            @Value("${spring.cloud.azure.active-directory.credential.client-id}") String clientId,
            @Value("${spring.cloud.azure.active-directory.credential.client-secret}") String clientSecret,
            @Value("${spring.cloud.azure.active-directory.profile.authority}${spring.cloud.azure.active-directory.profile.tenant-id}") String authority) throws Exception {
        accessTokenRetriever = new AccessTokenRetriever(clientId, clientSecret, authority);
    }

    public String getAccessToken(String scope) throws Exception {
        return accessTokenRetriever.getAccessToken(scope);
    }
}
