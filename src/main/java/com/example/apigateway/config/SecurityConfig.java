package com.example.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // Convert Keycloak roles into Spring Security authorities
        JwtAuthenticationConverter jwtAuthenticationConverter =
                new JwtAuthenticationConverter();

        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(
                new KeycloakRoleConverter()
        );

        http
                // Disable CSRF because this is a stateless REST API
                .csrf(csrf -> csrf.disable())

                .authorizeHttpRequests(auth -> auth

                        // PUBLIC ENDPOINTS
                        // Actuator endpoints
                        .requestMatchers("/actuator/**")
                        .permitAll()

                        // User registration does not require login
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/users/register"
                        )
                        .permitAll()

                        //ADMIN
                        .requestMatchers("/api/admin/**")
                        .hasRole("ADMIN")

                        //CONTENT CREATOR
                        .requestMatchers("/api/content/**")
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR"
                        )

                        // STUDENT
                
                        .requestMatchers("/api/student/**")
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR",
                                "STUDENT"
                        )


                       
                        // SUBJECT

                        // Read subjects
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/v1/subjects/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR",
                                "STUDENT"
                        )

                        // Create subjects
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/v1/subjects/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR"
                        )

                        // Update subjects
                        .requestMatchers(
                                HttpMethod.PUT,
                                "/api/v1/subjects/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR"
                        )

                        // Delete subjects
                        .requestMatchers(
                                HttpMethod.DELETE,
                                "/api/v1/subjects/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR"
                        )

                        // COURSES
                        // Read courses
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/v1/courses/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR",
                                "STUDENT"
                        )

                        // Create courses
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/v1/courses/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR"
                        )

                        // Update courses
                        .requestMatchers(
                                HttpMethod.PUT,
                                "/api/v1/courses/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR"
                        )

                        // Delete courses
                        .requestMatchers(
                                HttpMethod.DELETE,
                                "/api/v1/courses/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR"
                        )

                        // MODULES

                        // Read modules
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/v1/modules/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR",
                                "STUDENT"
                        )

                        // Create modules
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/v1/modules/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR"
                        )

                        // Update modules
                        .requestMatchers(
                                HttpMethod.PUT,
                                "/api/v1/modules/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR"
                        )

                        // Delete modules
                        .requestMatchers(
                                HttpMethod.DELETE,
                                "/api/v1/modules/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "CONTENT_CREATOR"
                        )

                        // ALL OTHER REQUESTS
                        // Everything else requires a valid JWT
                        .anyRequest()
                        .authenticated()
                )

                // KEYCLOAK JWT AUTHENTICATION
                

                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(jwt ->
                                jwt.jwtAuthenticationConverter(
                                        jwtAuthenticationConverter
                                )
                        )
                );

        return http.build();
    }
}