package com.pfernand.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    private final JwtConfig jwtConfig;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        final String header = request.getHeader(jwtConfig.getHeader());
        if (!isValidHeader(header)) {
            chain.doFilter(request, response);
            return;
        }

        final String token = header.replace(jwtConfig.getPrefix(), "");

        try {
            buildSecurityContext(token);
        } catch (Exception e) {
            SecurityContextHolder.clearContext();
        }
        chain.doFilter(request, response);
    }

    private boolean isValidHeader(final String header) {
        return header != null && header.startsWith(jwtConfig.getPrefix());
    }

    private void buildSecurityContext(final String token) {
        final Claims claims = Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(jwtConfig.getSecret()))
                .parseClaimsJws(token)
                .getBody();

        final String username = claims.getSubject();

        if (username != null) {
            @SuppressWarnings("unchecked") final List<String> authorities = (List<String>) claims.get("authorities");

            final UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(
                            username,
                            null,
                            authorities.stream()
                                    .map(SimpleGrantedAuthority::new)
                                    .collect(Collectors.toList())
                    );

            SecurityContextHolder.getContext().setAuthentication(auth);
        }
    }
}
