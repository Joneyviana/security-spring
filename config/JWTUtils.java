package com.security.config;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.security.auth.CustomUserDetailsService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@SuppressWarnings("Duplicates")
@Component
public class JWTUtils {

    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private Long expiration;

    @Autowired
    private CustomUserDetailsService usuarioService;

    private final String CLAIM_KEY_USERNAME = "sub";
    private final String CLAIM_KEY_ROLE = "role";
    private final String CLAIM_KEY_CREATED = "created";

    public JWTUtils() {

    }

    public String generateToken(String name) {

        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USERNAME, name);
        //usuarioService.loadUserByUsername(name).getAuthorities().forEach(authority -> claims.put(CLAIM_KEY_ROLE, authority.getAuthority()));
        claims.put(CLAIM_KEY_CREATED, new Date(System.currentTimeMillis()));

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(SignatureAlgorithm.HS512, secret.getBytes())
                .compact();
    }
/*
    public String refreshToken(OldTokenDTO oldTokenDTO) {
        String oldToken = oldTokenDTO.getOldToken().substring(7);
        String emailOrCPF = getUsername(oldToken);

        Usuario usuario = usuarioService.findByEmailOrCPFFromToken(emailOrCPF);

        Map<String, Object> claims = new HashMap<>();
        claims.put(CLAIM_KEY_USERNAME, emailOrCPF);
        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        for (Perfil perfil : usuario.getPerfis()) {
            authorities.add(new SimpleGrantedAuthority(perfil.getDescricao()));
        }
        claims.put(CLAIM_KEY_ROLE, authorities);
        claims.put(CLAIM_KEY_CREATED, new Date(System.currentTimeMillis()));
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(SignatureAlgorithm.HS512, secret.getBytes())
                .compact();

    }

 */

    public boolean tokenValidate(String token) {
        Claims claims = getClaims(token);
        if (claims != null) {
            String username = claims.getSubject();
            Date expirationDate = claims.getExpiration();
            Date now = new Date(System.currentTimeMillis());
            if (username != null && expirationDate != null && now.before(expirationDate)) {
                return true;
            }
        }
        return false;
    }

    public String getUsername(String token) {
        Claims claims = getClaims(token);
        if (claims != null) {
            return claims.getSubject();
        }
        return null;
    }

    public Date getTokenExpiration(String token) {
        Claims claims = getClaims(token);
        if (claims != null) {
            return claims.getExpiration();
        }
        return null;
    }

    private Claims getClaims(String token) {
        try {
            return Jwts.parser().setSigningKey(secret.getBytes()).parseClaimsJws(token).getBody();
        } catch (Exception e) {
            return null;
        }
    }
}
