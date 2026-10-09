package com.example.apigateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.RequestPredicate;
import org.springframework.web.servlet.function.RouterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

import static org.springframework.cloud.gateway.server.mvc.filter.BeforeFilterFunctions.uri;
import static org.springframework.cloud.gateway.server.mvc.handler.GatewayRouterFunctions.route;
import static org.springframework.cloud.gateway.server.mvc.handler.HandlerFunctions.http;
import static org.springframework.web.servlet.function.RequestPredicates.path;

@Configuration
public class CourseServiceRouteConfig {

    private final OAuth2AuthorizedClientManager authorizedClientManager;
    private final String courseServiceUrl;

    public CourseServiceRouteConfig(
            OAuth2AuthorizedClientManager authorizedClientManager,
            @Value("${course.service.url}") String courseServiceUrl) {

        this.authorizedClientManager = authorizedClientManager;
        this.courseServiceUrl = courseServiceUrl;
    }

    @Bean
    public RouterFunction<ServerResponse> courseServiceRoute() {

        RequestPredicate coursePaths =
                path("/api/v1/subjects/**")
                        .or(path("/api/v1/courses/**"))
                        .or(path("/api/v1/modules/**"));

        HandlerFilterFunction<ServerResponse, ServerResponse>
                serviceTokenFilter = (request, next) -> {

            try {

                OAuth2AuthorizeRequest authorizeRequest =
                        OAuth2AuthorizeRequest
                                .withClientRegistrationId(
                                        "api-gateway-service"
                                )
                                .principal("api-gateway-service")
                                .build();

                OAuth2AuthorizedClient authorizedClient =
                        authorizedClientManager.authorize(
                                authorizeRequest
                        );

                if (authorizedClient == null ||
                        authorizedClient.getAccessToken() == null) {

                    return ServerResponse
                            .status(
                                    HttpStatus.INTERNAL_SERVER_ERROR
                            )
                            .body(
                                    "Unable to obtain service access token"
                            );
                }

                String serviceToken =
                        authorizedClient
                                .getAccessToken()
                                .getTokenValue();

                ServerRequest modifiedRequest =
                        ServerRequest
                                .from(request)
                                .headers(headers -> {
                                    headers.remove(
                                            HttpHeaders.AUTHORIZATION
                                    );
                                    headers.setBearerAuth(
                                            serviceToken
                                    );
                                })
                                .build();

                return next.handle(modifiedRequest);

            } catch (Exception exception) {

                return ServerResponse
                        .status(
                                HttpStatus.INTERNAL_SERVER_ERROR
                        )
                        .body(
                                "Service-to-service authentication failed"
                        );
            }
        };

        return route("course-service")
                .route(coursePaths, http())
                .before(uri(courseServiceUrl))
                .filter(serviceTokenFilter)
                .build();
    }
}