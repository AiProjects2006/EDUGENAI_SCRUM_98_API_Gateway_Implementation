package com.example.apigateway.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * The gateway adds CORS headers itself and proxied services may add them again.
 * Browsers reject duplicated Access-Control-Allow-* values, so keep only one.
 */
@Configuration
public class SingleCorsHeaderConfig {

    private static final Set<String> SINGLE_VALUE_HEADERS = Set.of(
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-expose-headers",
            "access-control-max-age"
    );

    @Bean
    public FilterRegistrationBean<OncePerRequestFilter> singleCorsHeaderFilter() {
        OncePerRequestFilter filter = new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain) throws ServletException, IOException {
                chain.doFilter(request, new HttpServletResponseWrapper(response) {
                    @Override
                    public void addHeader(String name, String value) {
                        if (name != null && SINGLE_VALUE_HEADERS.contains(name.toLowerCase())) {
                            super.setHeader(name, value);
                        } else {
                            super.addHeader(name, value);
                        }
                    }
                });
            }
        };

        FilterRegistrationBean<OncePerRequestFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.addUrlPatterns("/*");
        return registration;
    }
}
