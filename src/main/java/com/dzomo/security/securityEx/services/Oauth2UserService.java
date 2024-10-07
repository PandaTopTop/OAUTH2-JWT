package com.dzomo.security.securityEx.services;

import com.dzomo.security.securityEx.models.MyUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.parameters.P;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
public class Oauth2UserService {

    @Autowired
    MyUserService myUserService;

    @Autowired
    JwtService jwtService;

   public String verifyOauth2User(OAuth2User oAuth2User) {

       String email = oAuth2User.getAttribute("email");
       String googleId =oAuth2User.getAttribute("sub");
    String username = oAuth2User.getAttribute("name");
       MyUser myUser = myUserService.findByEmail(email);

       if(myUser == null){
           myUser = new MyUser();
           myUser.setUsername(username);
           myUser.setEmail(email);
           myUser.setGoogleId(googleId);
           myUser.setProvider("google");
           myUserService.register(myUser);
       }

       return jwtService.generateToken(username);
   }
}
