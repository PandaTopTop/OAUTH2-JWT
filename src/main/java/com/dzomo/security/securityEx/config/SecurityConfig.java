package com.dzomo.security.securityEx.config;

import com.dzomo.security.securityEx.filters.JwtFilter;
import com.dzomo.security.securityEx.filters.OAuth2LoginSuccessHandler;
import com.dzomo.security.securityEx.services.JwtService;
import com.dzomo.security.securityEx.services.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@PropertySource("classpath:config.properties")
@PropertySource("classpath:application.properties")
public class SecurityConfig {
    @Autowired
    MyUserDetailsService myUserDetailsService;

    @Autowired
    JwtFilter jwtFiler;
    private final OAuth2LoginSuccessHandler successHandler;

    public SecurityConfig(@Lazy OAuth2LoginSuccessHandler successHandler) {
        this.successHandler = successHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {


        httpSecurity.csrf(x->x.disable());
//        httpSecurity.csrf(x->x.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
               httpSecurity. authorizeHttpRequests(request->request
                       .requestMatchers("/oauth2/**","/login/oauth2/code/google","login").permitAll()
                       .anyRequest().authenticated())
                       .addFilterBefore(jwtFiler, UsernamePasswordAuthenticationFilter.class);
        httpSecurity.oauth2Login( x-> x
//                .defaultSuccessUrl("/code/google", true));
//                .loginPage("/login")  // Your custom login page
                .successHandler(successHandler));
        httpSecurity.formLogin(Customizer.withDefaults());
        httpSecurity.httpBasic(Customizer.withDefaults());
        httpSecurity.addFilterAfter(jwtFiler, OAuth2LoginAuthenticationFilter.class);
        httpSecurity.sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

            httpSecurity.cors(cors->cors.configure(httpSecurity));

        return httpSecurity.build();

    }

//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails userDetails = User.builder()
////                withDefaultPasswordEncoder()
//                .username("rick")
//                .password("morty")
//                .roles("User").build();
//        UserDetails userDetails2 = User
//
//                .builder()
//                .username("123")
//                .password("123")
//                .roles("User").build();
//
//        List<UserDetails> userList = new ArrayList<>(List.of(userDetails, userDetails2));
//        return new InMemoryUserDetailsManager(userList);
//    }

@Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
}
    @Bean
    public AuthenticationProvider authenticationProvider(){

        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setPasswordEncoder(new BCryptPasswordEncoder(12));
        authenticationProvider.setUserDetailsService(myUserDetailsService);
        return authenticationProvider;
    }


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
