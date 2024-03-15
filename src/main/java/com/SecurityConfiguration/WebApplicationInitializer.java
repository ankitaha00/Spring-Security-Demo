package com.SecurityConfiguration;


import jakarta.servlet.Filter;

import org.springframework.web.filter.HiddenHttpMethodFilter;
import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

public class WebApplicationInitializer extends AbstractAnnotationConfigDispatcherServletInitializer {

    //for "root" application context configuration
    //The root application context typically contains shared/general resources like data sources, services, repositories, etc.
    @Override
    protected Class<?>[] getRootConfigClasses() {
        System.out.println("Inside getRootConfigClasses");
        return null;
    }

    //for DispatcherServlet application context configuration
    //The servlet context contains beans specific to this context, such as view resolvers, handler mappings, controllers, etc.
    @Override
    protected Class<?>[] getServletConfigClasses() {
        System.out.println("Inside getServletConfigClasses");
        return new Class[] { ApplicationConfiguration.class };        //Specify @Configuration and @Component classes for the Servlet application context.
    }

    @Override
    protected String[] getServletMappings() {                         //Specify the servlet mapping(s) for the DispatcherServlet — for example "/", "/app", etc.
        System.out.println("Inside getServletMappings");
        return new String[] { "/" };
    }

    @Override
    protected Filter[] getServletFilters() {
        System.out.println("Inside getServletFilters()");
        return new Filter[] { new HiddenHttpMethodFilter() };         //Specify filters to add and map to the DispatcherServlet.
    }

}