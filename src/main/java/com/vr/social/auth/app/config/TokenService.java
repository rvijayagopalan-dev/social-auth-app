package com.vr.social.auth.app.config;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

@Service
public class TokenService {
    private final SecretKey key;
    private final long ttlSeconds;

    public TokenService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.ttlSeconds}") long ttlSeconds
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.ttlSeconds = ttlSeconds;
    }

    public String createToken(Map<String, Object> claims, Instant now) {
        return Jwts.builder()
                .header().type("JWT").and()
                .claims(claims)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ttlSeconds)))
                .signWith(key)
                .compact();
    }

    public long getTtlSeconds() { return ttlSeconds; }
}