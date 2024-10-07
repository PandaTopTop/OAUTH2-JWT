package com.dzomo.security.securityEx.filters;

import com.dzomo.security.securityEx.models.MyUser;
import com.dzomo.security.securityEx.services.JwtService;
import com.dzomo.security.securityEx.services.MyUserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final MyUserService myUserService;

    public OAuth2LoginSuccessHandler(JwtService jwtService, MyUserService myUserService) {
        this.jwtService = jwtService;
        this.myUserService = myUserService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, IOException {
        // Cast to OAuth2AuthenticationToken to extract OAuth2 user details
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = oauthToken.getPrincipal();

        // Extract user details from OAuth2User
        String email = oAuth2User.getAttribute("email");
        String googleId = oAuth2User.getAttribute("sub");
        String username = oAuth2User.getAttribute("name");

        // Check if user exists in the database or create a new user
        MyUser myUser = myUserService.findByEmail(email);
        if (myUser == null) {
            myUser = new MyUser();
            myUser.setUsername(username);
            myUser.setEmail(email);
            myUser.setGoogleId(googleId);
            myUser.setProvider("google");
            myUserService.register(myUser);
        }

        // Generate JWT token
        String jwtToken = jwtService.generateToken(username);

        // Send JWT token back to the client (you can send it in a response header or redirect to frontend with token)
//        response.setHeader("Authorization", "Bearer " + jwtToken);
//        response.sendRedirect("/your-frontend-url?token=" + jwtToken);

        response.getWriter().write("{\"token\": \"" + jwtToken + "\"}");
        response.getWriter().flush();
    }
}