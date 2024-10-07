package com.dzomo.security.securityEx.repos;

import com.dzomo.security.securityEx.models.MyUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

//@Repository
public interface MyUserRepo extends JpaRepository<MyUser,Integer> {

    MyUser findByUsername(String username);
    MyUser findByEmail(String email);
}
