package pase.test.com.auth.web.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import pase.test.com.auth.web.security.UserDetailsServiceImpl;

@ExtendWith(MockitoExtension.class)
@DisplayName("JWT Authentication Filter Tests")
class JwtAuthenticationFilterTest {

    @Mock
    private JwtService jwtService;

    @Mock
    private UserDetailsServiceImpl userDetailsService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private UserDetails userDetails;

    @Mock
    private SecurityContext securityContext;

    @Mock
    private Authentication authentication;

    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @BeforeEach
    void setUp() {
        jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtService, userDetailsService);
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Should skip filtering for public endpoints")
    void shouldSkipFilteringForPublicEndpoints() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(request.getMethod()).thenReturn("POST");

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(jwtService, never()).validateTokenStructure(anyString());
    }

    @Test
    @DisplayName("Should skip filtering for OPTIONS requests")
    void shouldSkipFilteringForOptionsRequests() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("OPTIONS");

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(jwtService, never()).validateTokenStructure(anyString());
    }

    @Test
    @DisplayName("Should continue filtering when no Authorization header")
    void shouldContinueFilteringWhenNoAuthorizationHeader() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(jwtService, never()).validateTokenStructure(anyString());
    }

    @Test
    @DisplayName("Should continue filtering when Authorization header doesn't start with Bearer")
    void shouldContinueFilteringWhenAuthHeaderDoesntStartWithBearer() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Basic credentials");

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(jwtService, never()).validateTokenStructure(anyString());
    }

    @Test
    @DisplayName("Should continue filtering when token structure is invalid")
    void shouldContinueFilteringWhenTokenStructureIsInvalid() throws ServletException, IOException {
        String invalidToken = "invalid.token";
        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + invalidToken);
        when(jwtService.validateTokenStructure(invalidToken)).thenReturn(false);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(jwtService).validateTokenStructure(invalidToken);
        verify(jwtService, never()).isAccessToken(anyString());
    }

    @Test
    @DisplayName("Should continue filtering when token is not access token")
    void shouldContinueFilteringWhenTokenIsNotAccessToken() throws ServletException, IOException {
        String refreshToken = "valid.refresh.token";
        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + refreshToken);
        when(jwtService.validateTokenStructure(refreshToken)).thenReturn(true);
        when(jwtService.isAccessToken(refreshToken)).thenReturn(false);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(jwtService).validateTokenStructure(refreshToken);
        verify(jwtService).isAccessToken(refreshToken);
        verify(jwtService, never()).extractUsername(anyString());
    }

    @Test
    @DisplayName("Should authenticate user with valid JWT token")
    void shouldAuthenticateUserWithValidJwtToken() throws ServletException, IOException {
        String validToken = "valid.access.token";
        String username = "testuser";
        List<String> authorities = List.of("ROLE_USER", "user:read");

        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + validToken);
        when(jwtService.validateTokenStructure(validToken)).thenReturn(true);
        when(jwtService.isAccessToken(validToken)).thenReturn(true);
        when(jwtService.extractUsername(validToken)).thenReturn(username);
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);
        when(jwtService.isTokenValid(validToken, userDetails)).thenReturn(true);
        when(jwtService.extractAuthorities(validToken)).thenReturn(authorities);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(jwtService).validateTokenStructure(validToken);
        verify(jwtService).isAccessToken(validToken);
        verify(jwtService).extractUsername(validToken);
        verify(userDetailsService).loadUserByUsername(username);
        verify(jwtService).isTokenValid(validToken, userDetails);
        verify(jwtService).extractAuthorities(validToken);
        verify(securityContext).setAuthentication(any());
    }

    @Test
    @DisplayName("Should not authenticate when user already authenticated")
    void shouldNotAuthenticateWhenUserAlreadyAuthenticated() throws ServletException, IOException {
        String validToken = "valid.access.token";
        String username = "testuser";

        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + validToken);
        when(jwtService.validateTokenStructure(validToken)).thenReturn(true);
        when(jwtService.isAccessToken(validToken)).thenReturn(true);
        when(jwtService.extractUsername(validToken)).thenReturn(username);

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(authentication);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(userDetailsService, never()).loadUserByUsername(anyString());
        verify(securityContext, never()).setAuthentication(any());
    }

    @Test
    @DisplayName("Should continue filtering when username is null")
    void shouldContinueFilteringWhenUsernameIsNull() throws ServletException, IOException {
        String validToken = "valid.access.token";

        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + validToken);
        when(jwtService.validateTokenStructure(validToken)).thenReturn(true);
        when(jwtService.isAccessToken(validToken)).thenReturn(true);
        when(jwtService.extractUsername(validToken)).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(userDetailsService, never()).loadUserByUsername(anyString());
    }

    @Test
    @DisplayName("Should continue filtering when token is invalid")
    void shouldContinueFilteringWhenTokenIsInvalid() throws ServletException, IOException {
        String invalidToken = "invalid.access.token";
        String username = "testuser";

        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + invalidToken);
        when(jwtService.validateTokenStructure(invalidToken)).thenReturn(true);
        when(jwtService.isAccessToken(invalidToken)).thenReturn(true);
        when(jwtService.extractUsername(invalidToken)).thenReturn(username);
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);
        when(jwtService.isTokenValid(invalidToken, userDetails)).thenReturn(false);

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(securityContext, never()).setAuthentication(any());
    }

    @Test
    @DisplayName("Should handle JwtException gracefully")
    void shouldHandleJwtExceptionGracefully() throws ServletException, IOException {
        String validToken = "valid.access.token";

        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + validToken);
        when(jwtService.validateTokenStructure(validToken)).thenThrow(new JwtException("Token parsing failed"));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(userDetailsService, never()).loadUserByUsername(anyString());
    }

    @Test
    @DisplayName("Should handle UsernameNotFoundException gracefully")
    void shouldHandleUsernameNotFoundExceptionGracefully() throws ServletException, IOException {
        String validToken = "valid.access.token";
        String username = "nonexistent";

        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + validToken);
        when(jwtService.validateTokenStructure(validToken)).thenReturn(true);
        when(jwtService.isAccessToken(validToken)).thenReturn(true);
        when(jwtService.extractUsername(validToken)).thenReturn(username);
        when(userDetailsService.loadUserByUsername(username))
                .thenThrow(new UsernameNotFoundException("User not found"));

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(securityContext, never()).setAuthentication(any());
    }

    @Test
    @DisplayName("Should handle generic Exception gracefully")
    void shouldHandleGenericExceptionGracefully() throws ServletException, IOException {
        String validToken = "valid.access.token";

        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + validToken);
        when(jwtService.validateTokenStructure(validToken)).thenThrow(new RuntimeException("Unexpected error"));

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(userDetailsService, never()).loadUserByUsername(anyString());
    }

    @Test
    @DisplayName("Should identify public endpoints correctly")
    void shouldIdentifyPublicEndpointsCorrectly() throws ServletException {
        String[] publicPaths = {
                "/api/v1/auth/login",
                "/api/v1/auth/register",
                "/api/v1/auth/refresh",
                "/api/v1/auth/health",
                "/actuator/health",
                "/swagger-ui/index.html",
                "/v3/api-docs",
                "/favicon.ico",
                "/",
                "/error"
        };

        for (String path : publicPaths) {
            when(request.getRequestURI()).thenReturn(path);
            when(request.getMethod()).thenReturn("GET");

            boolean shouldNotFilter = jwtAuthenticationFilter.shouldNotFilter(request);
            assertThat(shouldNotFilter).isTrue();
        }
    }

    @Test
    @DisplayName("Should identify protected endpoints correctly")
    void shouldIdentifyProtectedEndpointsCorrectly() throws ServletException {
        String[] protectedPaths = {
                "/api/v1/auth/profile",
                "/api/v1/auth/logout",
                "/api/v1/orders",
                "/api/v1/management/users"
        };

        for (String path : protectedPaths) {
            when(request.getRequestURI()).thenReturn(path);
            when(request.getMethod()).thenReturn("GET");

            boolean shouldNotFilter = jwtAuthenticationFilter.shouldNotFilter(request);
            assertThat(shouldNotFilter).isFalse();
        }
    }

    @Test
    @DisplayName("Should handle empty Authorization header")
    void shouldHandleEmptyAuthorizationHeader() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("");

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(jwtService, never()).validateTokenStructure(anyString());
    }

    @Test
    @DisplayName("Should handle Bearer token with extra spaces")
    void shouldHandleBearerTokenWithExtraSpaces() throws ServletException, IOException {
        String token = "valid.access.token";
        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer  " + token);
        when(jwtService.validateTokenStructure(" " + token)).thenReturn(false);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verify(jwtService).validateTokenStructure(" " + token);
    }

    @Test
    @DisplayName("Should create authentication with correct authorities")
    void shouldCreateAuthenticationWithCorrectAuthorities() throws ServletException, IOException {
        String validToken = "valid.access.token";
        String username = "testuser";
        List<String> tokenAuthorities = List.of("ROLE_USER", "ROLE_ADMIN", "user:read", "user:write");

        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + validToken);
        when(jwtService.validateTokenStructure(validToken)).thenReturn(true);
        when(jwtService.isAccessToken(validToken)).thenReturn(true);
        when(jwtService.extractUsername(validToken)).thenReturn(username);
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);
        when(jwtService.isTokenValid(validToken, userDetails)).thenReturn(true);
        when(jwtService.extractAuthorities(validToken)).thenReturn(tokenAuthorities);
        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(securityContext).setAuthentication(any());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("Should handle null authorities from token")
    void shouldHandleNullAuthoritiesFromToken() throws ServletException, IOException {
        String validToken = "valid.access.token";
        String username = "testuser";

        when(request.getRequestURI()).thenReturn("/api/v1/protected");
        when(request.getMethod()).thenReturn("GET");
        when(request.getHeader("Authorization")).thenReturn("Bearer " + validToken);
        when(jwtService.validateTokenStructure(validToken)).thenReturn(true);
        when(jwtService.isAccessToken(validToken)).thenReturn(true);
        when(jwtService.extractUsername(validToken)).thenReturn(username);
        when(userDetailsService.loadUserByUsername(username)).thenReturn(userDetails);
        when(jwtService.isTokenValid(validToken, userDetails)).thenReturn(true);
        when(jwtService.extractAuthorities(validToken)).thenReturn(null);

        SecurityContextHolder.setContext(securityContext);
        when(securityContext.getAuthentication()).thenReturn(null);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }
}