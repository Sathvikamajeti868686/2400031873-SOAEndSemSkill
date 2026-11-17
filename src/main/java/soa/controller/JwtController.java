
package soa.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;

import soa.util.JwtUtil;
import soa.model.TokenRequest;

@RestController
@RequestMapping("/api/jwt")
public class JwtController {

    private final JwtUtil jwtUtil;

    public JwtController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    // Generate Token Endpoint
    @GetMapping("/generate")
    public String generateToken() {
        return jwtUtil.generateToken();
    }

    // Validate Token Endpoint
    @PostMapping("/validate")
    public ResponseEntity<?> validateToken(
            @RequestBody TokenRequest request) {

        try {
            Claims claims =
                jwtUtil.validateToken(request.getToken());

            Map<String, Object> response = new HashMap<>();

            response.put("message", "Token Valid");
            response.put("username", claims.getSubject());
            response.put("roles", claims.get("roles"));

            return ResponseEntity.ok(response);

        } catch (JwtException |
                 IllegalArgumentException e) {

            return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body("Invalid Token");
        }
    }
}
