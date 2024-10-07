package com.dzomo.security.securityEx.controllers;

import com.dzomo.security.securityEx.models.MyUser;
import com.dzomo.security.securityEx.services.JwtService;
import com.dzomo.security.securityEx.services.MyUserService;
import com.dzomo.security.securityEx.services.Oauth2UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MyUserController {

    @Autowired
    MyUserService myUserService;

    @Autowired
    Oauth2UserService oauth2UserService;

@Autowired
JwtService jwtService;

    BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);
    @PostMapping("/register")
    public MyUser register(@RequestBody MyUser myUser){

            myUser.setPassword(passwordEncoder.encode(myUser.getPassword()));
            return myUserService.register(myUser);
    }

//    @PostMapping("/login")
//    public String login(@RequestBody MyUser myUser){
//
//       return myUserService.verify(myUser);
//
//    }

//    @GetMapping("/login/oauth2/code/google")
//    public String auth( OAuth2AuthenticationToken authentication){
//        OAuth2User oAuth2User = authentication.getPrincipal();
//        return oauth2UserService.verifyOauth2User(oAuth2User);
//    }
@GetMapping("/code/google")
public ResponseEntity<String> oauth2Callback(OAuth2AuthenticationToken token) {
    String username = token.getPrincipal().getAttribute("name");
    String email = token.getPrincipal().getAttribute("email");
    String googleId = token.getPrincipal().getAttribute("sub");

    // Find or create the user in your database
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

    // Return the JWT token in the response
    return ResponseEntity.ok(jwtToken);
}
}
