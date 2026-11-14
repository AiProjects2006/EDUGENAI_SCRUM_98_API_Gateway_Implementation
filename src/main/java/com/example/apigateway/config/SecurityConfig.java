package com.example.apigateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.List;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @org.springframework.beans.factory.annotation.Value("${app.security.open-course-api:true}")
    private boolean openCourseApi;

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
                .cors(Customizer.withDefaults())

                .authorizeHttpRequests(auth -> {

                        // PUBLIC ENDPOINTS
                        // Actuator endpoints
                        auth.requestMatchers("/actuator/**").permitAll();

                        // User & Backoffice registration, login, token refresh, and auth endpoints do not require prior authentication
                        auth.requestMatchers(
                                HttpMethod.POST,
                                "/api/users/register",
                                "/api/users/login",
                                "/api/users/keycloak-sync",
                                "/api/users/refresh",
                                "/api/auth/**",
                                "/api/v1/backoffice/auth/**",
                                "/api/v1/backoffice/users/register"
                        ).permitAll();

                        // DEV ONLY: Public access when app.security.open-course-api=true in application.properties
                        if (openCourseApi) {
                            auth.requestMatchers(
                                    "/api/v1/subjects/**",
                                    "/api/v1/courses/**",
                                    "/api/v1/modules/**",
                                    "/api/v1/backoffice/**",
                                    "/api/resources/**",
                                    "/api/v1/resources/**",
                                    "/api/ai-resources/**",
                                    "/api/v1/activities/**",
                                    "/api/v1/enrollments/**",
                                    "/api/v1/preferences/**",
                                    "/api/v1/subscriptions/**"
                            ).permitAll();
                        }

                        // BACKOFFICE BFF (Admin & Content Creator)
                        auth.requestMatchers("/api/v1/backoffice/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR");

                        // ENROLLMENTS
                        auth.requestMatchers("/api/v1/enrollments/**", "/api/v1/preferences/**", "/api/v1/subscriptions/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR", "STUDENT");

                        // ADMIN
                        auth.requestMatchers("/api/admin/**")
                                .hasRole("ADMIN");

                        // CONTENT CREATOR
                        auth.requestMatchers("/api/content/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR");

                        // STUDENT
                        auth.requestMatchers("/api/student/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR", "STUDENT");

                        // SUBJECT
                        // Read subjects
                        auth.requestMatchers(HttpMethod.GET, "/api/v1/subjects/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR", "STUDENT");

                        // Create subjects
                        auth.requestMatchers(HttpMethod.POST, "/api/v1/subjects/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR");

                        // Update subjects
                        auth.requestMatchers(HttpMethod.PUT, "/api/v1/subjects/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR");

                        // Delete subjects
                        auth.requestMatchers(HttpMethod.DELETE, "/api/v1/subjects/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR");

                        // COURSES
                        // Read courses
                        auth.requestMatchers(HttpMethod.GET, "/api/v1/courses/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR", "STUDENT");

                        // Create courses
                        auth.requestMatchers(HttpMethod.POST, "/api/v1/courses/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR");

                        // Update courses
                        auth.requestMatchers(HttpMethod.PUT, "/api/v1/courses/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR");

                        // Delete courses
                        auth.requestMatchers(HttpMethod.DELETE, "/api/v1/courses/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR");

                        // MODULES
                        // Read modules
                        auth.requestMatchers(HttpMethod.GET, "/api/v1/modules/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR", "STUDENT");

                        // Create modules
                        auth.requestMatchers(HttpMethod.POST, "/api/v1/modules/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR");

                        // Update modules
                        auth.requestMatchers(HttpMethod.PUT, "/api/v1/modules/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR");

                        // Delete modules
                        auth.requestMatchers(HttpMethod.DELETE, "/api/v1/modules/**")
                                .hasAnyRole("ADMIN", "CONTENT_CREATOR");

                        // ALL OTHER REQUESTS
                        // Everything else requires a valid JWT
                        auth.anyRequest().authenticated();
                })

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

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of("http://localhost:*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
