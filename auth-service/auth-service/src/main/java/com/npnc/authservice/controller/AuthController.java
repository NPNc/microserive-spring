package com.npnc.authservice.controller;

import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name="Test-Auth-Api")
@RestController
@RequestMapping("test-auth")
public class AuthController {

    @GetMapping("/login")
    @PreAuthorize("hasRole('user')")
    public String login(){
        return "Login";
    }

    @GetMapping("/admin-login")
    @PreAuthorize("hasRole('admin')")
    public String adminLogin(){
        return "Admin Login";
    }
}
