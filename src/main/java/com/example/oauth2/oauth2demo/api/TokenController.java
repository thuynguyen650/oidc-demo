package com.example.oauth2.oauth2demo.api;

import com.example.oauth2.oauth2demo.services.AzureAdService;
import com.microsoft.graph.authentication.TokenCredentialAuthProvider;
import com.microsoft.graph.models.User;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Scanner;

@RestController
public class TokenController {
    private final AzureAdService azureAdService;
    private static final String GRAPH_API_URL = "https://graph.microsoft.com/v1.0/";

    public TokenController(AzureAdService azureAdService) {
        this.azureAdService = azureAdService;
    }
    @GetMapping("/abcd")
    public String getAccessToken() throws Exception {
        String accessToken = azureAdService.getAccessToken("https://graph.microsoft.com");

        try {
            // Make a GET request to the Microsoft Graph API
            URL url = new URL(GRAPH_API_URL + "me");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            conn.setRequestProperty("Accept", "application/json");

            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                // Read the response
                Scanner scanner = new Scanner(conn.getInputStream());
                StringBuilder response = new StringBuilder();
                while (scanner.hasNextLine()) {
                    response.append(scanner.nextLine());
                }
                scanner.close();

                // Parse and process the response as needed
                return response.toString();
            } else {
                try (BufferedReader errorReader = new BufferedReader(new InputStreamReader(conn.getErrorStream()))) {
                    String inputLine;
                    StringBuilder errorResponse = new StringBuilder();
                    while ((inputLine = errorReader.readLine()) != null) {
                        errorResponse.append(inputLine);
                    }
                    // Print the error response body
                    return "Error Response Body: " + errorResponse.toString();
                }
            }
        } catch (IOException e) {
            // Handle exception
            e.printStackTrace();
        }
        return "Access token: " + accessToken;
    }
}
