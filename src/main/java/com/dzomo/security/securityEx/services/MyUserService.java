package com.dzomo.security.securityEx.services;

import com.dzomo.security.securityEx.models.MyUser;
import com.dzomo.security.securityEx.models.MyUserPrincipal;
import com.dzomo.security.securityEx.repos.MyUserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
public class MyUserService {
    @Autowired
    MyUserRepo myUserRepo;

    @Autowired
    AuthenticationManager authManager;

    @Autowired
    private JwtService jwtService;
    public MyUser register(MyUser myUser){

        return myUserRepo.save(myUser);
    }

    public MyUser findByEmail(String email){
        return myUserRepo.findByEmail(email);
    }

    public String verify(MyUser myUser) {
        Authentication authentication = authManager
                .authenticate(new UsernamePasswordAuthenticationToken(myUser.getUsername(), myUser.getPassword()));

        if(authentication.isAuthenticated()){
            return jwtService.generateToken(authentication.getName());
        } return "fail";
    }
}
