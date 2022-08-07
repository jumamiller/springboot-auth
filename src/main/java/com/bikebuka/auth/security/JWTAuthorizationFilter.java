package com.bikebuka.auth.security;

import io.jsonwebtoken.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JWTAuthorizationFilter extends OncePerRequestFilter {
    private final String HEADER="Authorization";
    private final String PREFIX="Bearer ";

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain
                                    ) throws ServletException, IOException {
        try{
            if (checkJWTToken(httpServletRequest)) {
                Claims claims=validateToken(httpServletRequest);
                if (claims.get("authorities")!=null) {
                    setupSpringAuthentication(claims);
                } else{
                    SecurityContextHolder.clearContext();
                }
            }else{
                SecurityContextHolder.clearContext();
            }
            filterChain.doFilter(httpServletRequest,httpServletResponse);
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException jwtException) {
            httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
            httpServletResponse.sendError(HttpServletResponse.SC_FORBIDDEN,jwtException.getMessage());
        }
    }

    /**
     *
     * @param claims
     */
    private void setupSpringAuthentication(Claims claims){
        @SuppressWarnings("unchecked")
        List<String> authorities= (List<String>) claims.get("authorities");
        UsernamePasswordAuthenticationToken auth=new UsernamePasswordAuthenticationToken(claims.getSubject(),
                null,
                authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList())
        );
        SecurityContextHolder.getContext().setAuthentication(auth);

    }

    /**
     *
     * @param httpServletRequest
     * @return
     */
    private Claims validateToken(HttpServletRequest httpServletRequest) {
        String jwtToken=httpServletRequest
                .getHeader(HEADER)
                .replace(PREFIX,"");
        String SECRET = "secret";
        return Jwts
                .parser()
                .setSigningKey(SECRET.getBytes())
                .parseClaimsJws(jwtToken)
                .getBody();
    }

    /**
     *
     * @param httpServletRequest
     * @return
     */
    private boolean checkJWTToken(HttpServletRequest httpServletRequest){
        String authenticatedHeader= httpServletRequest.getHeader(HEADER);
        if(authenticatedHeader==null || !authenticatedHeader.startsWith(PREFIX)) {
            return false;
        }
        return true;
    }
}
