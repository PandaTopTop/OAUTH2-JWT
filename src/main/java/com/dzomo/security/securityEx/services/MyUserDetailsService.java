package com.dzomo.security.securityEx.services;

import com.dzomo.security.securityEx.models.MyUser;
import com.dzomo.security.securityEx.models.MyUserPrincipal;
import com.dzomo.security.securityEx.repos.MyUserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {
    @Autowired
   private MyUserRepo myUserRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

       MyUser myUser = myUserRepo.findByUsername(username);

       if(myUser == null){
           System.out.println("No user found with username: " + username);
           throw  new UsernameNotFoundException(username);
       }
        MyUserPrincipal myUserPrincipal = new MyUserPrincipal(myUser);

        return myUserPrincipal;
    }
}
