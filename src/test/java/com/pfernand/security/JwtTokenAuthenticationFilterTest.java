package com.pfernand.security;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

@RunWith(MockitoJUnitRunner.class)
public class JwtTokenAuthenticationFilterTest {

    private static final String PREFIX = "Bearer";
    private static final String HEADER = "Authorization";
    private static final String TOKEN = PREFIX + "eyJ0eXAiOiJCZWFyZXIiLCJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJ1cm46cGZlcm5hbmQ6d3c6Y3N0OmFkbWluIiwiYXV0aG9yaXRpZXMiOlsiYWRtaW4iXSwianRpIjoiNDlhYjEyZmEtZjI2NS00MDk1LTgwYTktYTEwY2Q5YTZkY2RlIiwiYXVkIjoidXJuOnBmZXJuYW5kOnd3IiwiaXNzIjoidXJuOnBmZXJuYW5kOnd3OmF1dGgtc2VydmVyIiwibmJmIjoxNTUyNjAxNjE4LCJpYXQiOjE1NTI2MDE2MTksImV4cCI6MTU1NjIwMTYxOX0.QfShQX9TkAg7_NYQe6ES0UwFROAy5enfp9i1DhAyIGI_b16V6jI_51vD2Tl729bHuLbmFj9TPv_6wQbYjcKofQ";
    private static final String SECRET = "JwtSecretKey";

    @Mock
    private JwtConfig jwtConfig;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse httpServletResponse;

    @Mock
    private FilterChain filterChain;

    @InjectMocks
    private JwtTokenAuthenticationFilter jwtTokenAuthenticationFilter;

    @Before
    public void setUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void doFilterInternalWhenHeaderIsNullThenReturnWithoutContext() throws Exception {
        // Given
        // When
        Mockito.when(jwtConfig.getHeader())
                .thenReturn(HEADER);
        Mockito.when(request.getHeader(HEADER))
                .thenReturn(null);

        jwtTokenAuthenticationFilter.doFilterInternal(request, httpServletResponse, filterChain);

        // Then
        Mockito.verify(filterChain, Mockito.times(1))
                .doFilter(request, httpServletResponse);
        Mockito.verify(jwtConfig, Mockito.times(0))
                .getPrefix();
        Mockito.verify(jwtConfig, Mockito.times(0))
                .getSecret();
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void doFilterInternalWhenHeaderIsInvalidThenReturnWithoutContext() throws Exception {
        // Given
        // When
        Mockito.when(jwtConfig.getHeader())
                .thenReturn(HEADER);
        Mockito.when(jwtConfig.getPrefix())
                .thenReturn(PREFIX);
        Mockito.when(request.getHeader(HEADER))
                .thenReturn("header");

        jwtTokenAuthenticationFilter.doFilterInternal(request, httpServletResponse, filterChain);

        // Then
        Mockito.verify(filterChain, Mockito.times(1))
                .doFilter(request, httpServletResponse);
        Mockito.verify(jwtConfig, Mockito.times(1))
                .getPrefix();
        Mockito.verify(jwtConfig, Mockito.times(0))
                .getSecret();
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void doFilterInternalWhenHeaderIsValidThenReturnBuildContext() throws Exception {
        // Given
        final String username = "urn:pfernand:ww:cst:admin";
        final UsernamePasswordAuthenticationToken auth =
                new UsernamePasswordAuthenticationToken(
                        username,
                        null,
                        Collections.singletonList(new SimpleGrantedAuthority("admin"))
                );
        // When
        Mockito.when(jwtConfig.getHeader())
                .thenReturn(HEADER);
        Mockito.when(jwtConfig.getPrefix())
                .thenReturn(PREFIX);
        Mockito.when(request.getHeader(HEADER))
                .thenReturn(TOKEN);
        Mockito.when(jwtConfig.getSecret())
                .thenReturn(SECRET);

        jwtTokenAuthenticationFilter.doFilterInternal(request, httpServletResponse, filterChain);

        // Then
        Mockito.verify(filterChain, Mockito.times(1))
                .doFilter(request, httpServletResponse);
        Mockito.verify(jwtConfig, Mockito.times(2))
                .getPrefix();
        Mockito.verify(jwtConfig, Mockito.times(1))
                .getSecret();
        assertTrue(SecurityContextHolder.getContext().getAuthentication().isAuthenticated());
        assertEquals(auth, SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    public void doFilterInternalWhenBuildSecurityContextFailsReturnWithoutContext() throws Exception {
        // Given
        // When
        Mockito.when(jwtConfig.getHeader())
                .thenReturn(HEADER);
        Mockito.when(jwtConfig.getPrefix())
                .thenReturn(PREFIX);
        Mockito.when(request.getHeader(HEADER))
                .thenReturn(TOKEN);
        Mockito.when(jwtConfig.getSecret())
                .thenThrow(new RuntimeException("error"));

        jwtTokenAuthenticationFilter.doFilterInternal(request, httpServletResponse, filterChain);

        // Then
        Mockito.verify(filterChain, Mockito.times(1))
                .doFilter(request, httpServletResponse);
        Mockito.verify(jwtConfig, Mockito.times(2))
                .getPrefix();
        Mockito.verify(jwtConfig, Mockito.times(1))
                .getSecret();
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

}