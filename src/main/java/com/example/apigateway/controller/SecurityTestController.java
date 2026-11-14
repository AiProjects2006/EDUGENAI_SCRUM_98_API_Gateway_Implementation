package com.example.apigateway.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SecurityTestController {

    @GetMapping("/api/admin/test")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminTest() {
        return "ADMIN access granted";
    }

    @GetMapping("/api/student/test")
    @PreAuthorize("hasRole('STUDENT')")
    public String studentTest() {
        return "STUDENT access granted";
    }

    @GetMapping("/api/content/test")
    @PreAuthorize("hasRole('CONTENT_CREATOR')")
    public String contentCreatorTest() {
        return "CONTENT_CREATOR access granted";
    }
}