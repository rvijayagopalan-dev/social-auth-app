package com.vr.social.auth.app.controller;

import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("/api/me")
    public Map<String, Object> me(@AuthenticationPrincipal OidcUser user) {
        if (user == null) return Map.of("authenticated", false);
        return Map.of(
                "authenticated", true,
                "sub", user.getSubject(),
                "name", user.getFullName(),
                "email", user.getEmail(),
                "picture", user.getPicture()
        );
    }
}