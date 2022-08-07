package com.bikebuka.auth.controller;

import com.bikebuka.auth.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@RestController
public class UserController {
    @PostMapping("/api/v1/auth/login")
    public User login(@RequestParam("username") String username, @RequestParam("password") String password) {
        String token=getJWTToken(username);
        User user=new User();
        user.setUsername(username);
        user.setToken(token);
        return user;
    }

    /**
     * Get JWT
     * @param username
     * @return
     */
    private String getJWTToken(String username) {
        String secretKey="secret";
        List<GrantedAuthority> grantedAuthorities= AuthorityUtils
                .commaSeparatedStringToAuthorityList("ROLE_USER");
        String token=Jwts
                .builder()
                .setId("JWT")
                .setSubject(username)
                .claim("authorities",
                        grantedAuthorities.stream()
                                .map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList()))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+600000))
                .signWith(SignatureAlgorithm.HS512,secretKey.getBytes())
                .compact();

        return "Bearer " + token;
    }
}
