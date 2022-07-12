package com.mohammed.authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
public class ProjectConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public UserDetailsService userDetailsService() {
        var manager = new InMemoryUserDetailsManager();

        var user1 = User.withUsername("mohamed")
                .password("12345")
//                .authorities("READ")
//                .authorities("ROLE_ADMIN") // you can use .roles("ADMIN") with no ROLE_ prefix
                .roles("ADMIN") // or you can write this as .authorities("ROLE_ADMIN") YOU MUST USE ROLE_ Prefix
                .build();

        var user2 = User.withUsername("ahmed")
                .password("12345")
                .authorities("READ", "WRITE")
                .build();

        var user3 = User.withUsername("mido")
                .password("12345")
                .roles("MANAGER")
                .build();

        manager.createUser(user1);
        manager.createUser(user2);
        manager.createUser(user3);

        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic();
        // Approve all requests even the unauthenticated one
//        http.authorizeRequests().anyRequest().permitAll();

        // Deny All Requests
//        http.authorizeRequests().anyRequest().denyAll();

        // Only users having that authority can call the endpoint.
//        http.authorizeRequests().anyRequest().hasAuthority("READ");

        // The user must have at least one of the specified authorities to make a request.
//        http.authorizeRequests().anyRequest().hasAnyAuthority("READ", "WRITE");

        // Only users with this ROLE can call the endpoint.
//        http.authorizeRequests().anyRequest().hasRole("ADMIN");

        // Only users with at least one ROLE of the specified ROLES can call the endpoint.
        http.authorizeRequests().anyRequest().hasAnyRole("ADMIN", "MANAGER");

        // SpEL expression to be passed to access method
        // Don't use access if you can achieve the requirements with authorities() and roles() methods.
        // this expression and access can be achieved using hasAnyRole("ADMIN", "MANAGER") but just as a proof of concept
//        String expression = "hasRole('ADMIN') or hasRole('MANAGER')";
//        http.authorizeRequests().anyRequest().access(expression);

    }

}
