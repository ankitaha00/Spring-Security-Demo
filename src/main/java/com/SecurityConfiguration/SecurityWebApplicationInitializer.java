package com.SecurityConfiguration;


import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.session.HttpSessionEventPublisher;

public class SecurityWebApplicationInitializer extends AbstractSecurityWebApplicationInitializer {          //This only registers the springSecurityFilterChain for every URL in your application

    @Override
    protected boolean enableHttpSessionEventPublisher() {
        System.out.println("Inside enableHttpSessionEventPublisher");
        return true;
    }

}