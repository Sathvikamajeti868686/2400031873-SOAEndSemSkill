
package soa.util;

import java.util.Date;
import java.util.Arrays;

import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import javax.crypto.SecretKey;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    private SecretKey getKey() {
        return Keys.hmacShaKeyFor(
            Decoders.BASE64.decode(secret)
        );
    }

    // Generate JWT Token
    public String generateToken() {

        return Jwts.builder()
            .subject("Sathvika")
            .claim("roles", Arrays.asList("USER"))
            .issuedAt(new Date())
            .expiration(
                new Date(System.currentTimeMillis() + 3600000)
            )
            .signWith(getKey())
            .compact();
    }

    // Validate JWT Token
    public Claims validateToken(String token) {

        return Jwts.parser()
            .verifyWith(getKey())
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }
}
