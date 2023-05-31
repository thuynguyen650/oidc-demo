package com.example.oauth2.oauth2demo.utils;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.DeviceCodeCredential;
import com.azure.identity.DeviceCodeCredentialBuilder;
import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.graph.authentication.IAuthenticationProvider;
import com.microsoft.graph.authentication.TokenCredentialAuthProvider;
import com.microsoft.graph.models.User;
import com.microsoft.graph.requests.GraphServiceClient;
import com.microsoft.graph.requests.UserRequest;
import okhttp3.Request;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class AccessTokenRetriever {
    private final ConfidentialClientApplication clientApplication;


    private final static List<String> SCOPES;

    static {
        SCOPES = Arrays.asList("https://graph.microsoft.com/.default");
    }
    public AccessTokenRetriever(String clientId, String clientSecret, String authority) throws Exception {
        clientApplication = ConfidentialClientApplication.builder(clientId, ClientCredentialFactory.createFromSecret(clientSecret))
                .authority(authority)
                .build();
    }

    public String getAccessToken(String resource) throws Exception {
        String scope = resource + "/.default";
        ClientCredentialParameters parameters = ClientCredentialParameters.builder(Collections.singleton(scope)).build();
        IAuthenticationResult authenticationResult = clientApplication.acquireToken(parameters).join();
        return authenticationResult.accessToken();
    }
}
