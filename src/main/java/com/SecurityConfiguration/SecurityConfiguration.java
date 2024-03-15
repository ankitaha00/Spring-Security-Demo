package com.SecurityConfiguration;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collections;

@Configuration
@EnableWebMvc
@EnableWebSecurity
public class SecurityConfiguration  {

    @Bean
    public UserDetailsService userDetailsService() {
        System.out.println("Inside UserDetailsService");

        UserDetails user = User.withDefaultPasswordEncoder()        //to ensure that the password stored in memory is protected, but it does not protect against obtaining the password by decompiling the source code.
                .username("user")
                .password("0000")
                .roles("USER")
                .build();
        System.out.println("USER : " + "U: " + user.getUsername() + " P: " + user.getPassword() + " " + user.getAuthorities());

        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("0000")
                .roles("ADMIN")
                .build();
        System.out.println("ADMIN : " + admin);

        return new InMemoryUserDetailsManager(user, admin);
    }

//    @Bean
//    public PasswordEncoder passwordEncoder() {
//
//        return new BCryptPasswordEncoder();
//    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        System.out.println("Inside SecurityFilterChain");
        http.csrf(Customizer.withDefaults());
        http
                .authorizeHttpRequests((authz) -> authz
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/user").hasRole("USER")
                        .requestMatchers("/public").permitAll()
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated()
                )
                .httpBasic(Customizer.withDefaults())
//                .formLogin(Customizer.withDefaults());
                .formLogin(
                        form -> form
                                .loginPage("/login")
                                .failureForwardUrl("/error")
                                .permitAll());


        return http.build();
    }

}