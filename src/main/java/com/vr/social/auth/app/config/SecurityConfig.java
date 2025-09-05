package com.vr.social.auth.app.config;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${app.frontendUrl}")
    private String frontendUrl;

    @Value("${app.jwt.cookieName}")
    private String cookieName;

    @Value("${app.jwt.secure:false}")
    private boolean cookieSecure;

    @Value("${app.jwt.sameSite:Lax}")
    private String sameSite;

    private final TokenService tokenService;

    public SecurityConfig(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/health", "/").permitAll()
                .requestMatchers("/api/me").authenticated()
                .anyRequest().permitAll()
                )
                .oauth2Login(oauth -> oauth
                .userInfoEndpoint(user -> user.oidcUserService(this.oidcUserService()))
                .successHandler(this.authSuccessHandler())
                )
                .logout(logout -> logout
                .logoutUrl("/api/logout")
                .logoutSuccessHandler((req, res, auth) -> {
                    clearCookie(res);
                    res.setStatus(HttpServletResponse.SC_OK);
                })
                );
        return http.build();
    }

    private OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        OidcUserService delegate = new OidcUserService();
        return userRequest -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            // Custom logic or mapping can go here
            return oidcUser;
        };
    }

    private AuthenticationSuccessHandler authSuccessHandler() {
        return (HttpServletRequest request, HttpServletResponse response, Authentication authentication) -> {
            OidcUser user = (OidcUser) authentication.getPrincipal();
            Map<String, Object> claims = Map.of(
                    "sub", user.getSubject(),
                    "name", user.getFullName(),
                    "email", user.getEmail(),
                    "picture", user.getPicture()
            );
            String jwt = tokenService.createToken(claims, Instant.now());
            setCookie(response, jwt);
            response.sendRedirect(frontendUrl);
        };
    }

    private void setCookie(HttpServletResponse response, String jwt) throws IOException {
        Cookie cookie = new Cookie(cookieName, jwt);
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieSecure);
        cookie.setPath("/");
        cookie.setMaxAge((int) tokenService.getTtlSeconds());
        response.addHeader("Set-Cookie", cookie.getName() + "=" + cookie.getValue() + "; Path=/; Max-Age=" + cookie.getMaxAge() + "; HttpOnly;" + (cookieSecure ? " Secure;" : "") + " SameSite=" + sameSite);
    }

    private void clearCookie(HttpServletResponse response) {
        response.addHeader("Set-Cookie", cookieName + "=; Path=/; Max-Age=0; HttpOnly;" + (cookieSecure ? " Secure;" : "") + " SameSite=" + sameSite);
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(
            @Value("${app.frontendUrl}") String origin
    ) {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(List.of(origin));
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("Content-Type", "Authorization"));
        cfg.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }
}
