package pase.test.com.auth.web.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import io.jsonwebtoken.JwtException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
@DisplayName("JWT Service Tests")
class JwtServiceTest {

    @Mock
    private UserDetails userDetails;

    private JwtService jwtService;

    private final String testSecretKey = "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970";
    private final String testIssuer = "test-auth-service";
    private final long accessTokenExpiration = 900000L;
    private final long refreshTokenExpiration = 604800000L;

    @BeforeEach
    void setUp() {
        jwtService = new JwtService();
        ReflectionTestUtils.setField(jwtService, "secretKey", testSecretKey);
        ReflectionTestUtils.setField(jwtService, "issuer", testIssuer);
        ReflectionTestUtils.setField(jwtService, "accessTokenExpiration", accessTokenExpiration);
        ReflectionTestUtils.setField(jwtService, "refreshTokenExpiration", refreshTokenExpiration);
    }

    @Test
    @DisplayName("Should generate access token successfully")
    void shouldGenerateAccessTokenSuccessfully() {
        String username = "testuser";
        List<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("user:read")
        );

        when(userDetails.getUsername()).thenReturn(username);
        //when(userDetails.getAuthorities()).thenReturn(authorities);

        String token = jwtService.generateAccessToken(userDetails);

        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();
        assertThat(token.split("\\.")).hasSize(3);
    }

    @Test
    @DisplayName("Should generate refresh token successfully")
    void shouldGenerateRefreshTokenSuccessfully() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);

        String token = jwtService.generateRefreshToken(userDetails);

        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();
        assertThat(token.split("\\.")).hasSize(3);
    }

    @Test
    @DisplayName("Should extract username from token")
    void shouldExtractUsernameFromToken() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        String token = jwtService.generateAccessToken(userDetails);
        String extractedUsername = jwtService.extractUsername(token);

        assertThat(extractedUsername).isEqualTo(username);
    }

    @Test
    @DisplayName("Should extract expiration from token")
    void shouldExtractExpirationFromToken() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        Date beforeGeneration = new Date();
        String token = jwtService.generateAccessToken(userDetails);
        Date extractedExpiration = jwtService.extractExpiration(token);

        assertThat(extractedExpiration).isAfter(beforeGeneration);
        assertThat(extractedExpiration.getTime() - beforeGeneration.getTime())
                .isGreaterThan(accessTokenExpiration - 1000);
    }

    @Test
    @DisplayName("Should extract token type from access token")
    void shouldExtractTokenTypeFromAccessToken() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        String token = jwtService.generateAccessToken(userDetails);
        String tokenType = jwtService.extractTokenType(token);

        assertThat(tokenType).isEqualTo("ACCESS");
    }

    @Test
    @DisplayName("Should extract token type from refresh token")
    void shouldExtractTokenTypeFromRefreshToken() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);

        String token = jwtService.generateRefreshToken(userDetails);
        String tokenType = jwtService.extractTokenType(token);

        assertThat(tokenType).isEqualTo("REFRESH");
    }

    @Test
    @DisplayName("Should validate token successfully")
    void shouldValidateTokenSuccessfully() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        String token = jwtService.generateAccessToken(userDetails);
        boolean isValid = jwtService.isTokenValid(token, userDetails);

        assertThat(isValid).isTrue();
    }

    @Test
    @DisplayName("Should return false for invalid username in token validation")
    void shouldReturnFalseForInvalidUsernameInTokenValidation() {
        String username = "testuser";
        String differentUsername = "differentuser";

        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        String token = jwtService.generateAccessToken(userDetails);

        when(userDetails.getUsername()).thenReturn(differentUsername);
        boolean isValid = jwtService.isTokenValid(token, userDetails);

        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("Should check if token is not expired")
    void shouldCheckIfTokenIsNotExpired() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        String token = jwtService.generateAccessToken(userDetails);
        boolean isExpired = jwtService.isTokenExpired(token);

        assertThat(isExpired).isFalse();
    }

    @Test
    @DisplayName("Should identify access token correctly")
    void shouldIdentifyAccessTokenCorrectly() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        String token = jwtService.generateAccessToken(userDetails);
        boolean isAccessToken = jwtService.isAccessToken(token);

        assertThat(isAccessToken).isTrue();
    }

    @Test
    @DisplayName("Should identify refresh token correctly")
    void shouldIdentifyRefreshTokenCorrectly() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);

        String token = jwtService.generateRefreshToken(userDetails);
        boolean isRefreshToken = jwtService.isRefreshToken(token);

        assertThat(isRefreshToken).isTrue();
    }

    @Test
    @DisplayName("Should return false when checking if access token is refresh token")
    void shouldReturnFalseWhenCheckingIfAccessTokenIsRefreshToken() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        String token = jwtService.generateAccessToken(userDetails);
        boolean isRefreshToken = jwtService.isRefreshToken(token);

        assertThat(isRefreshToken).isFalse();
    }

    @Test
    @DisplayName("Should return false when checking if refresh token is access token")
    void shouldReturnFalseWhenCheckingIfRefreshTokenIsAccessToken() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);

        String token = jwtService.generateRefreshToken(userDetails);
        boolean isAccessToken = jwtService.isAccessToken(token);

        assertThat(isAccessToken).isFalse();
    }

    @Test
    @DisplayName("Should get token expiration as LocalDateTime")
    void shouldGetTokenExpirationAsLocalDateTime() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        LocalDateTime beforeGeneration = LocalDateTime.now();
        String token = jwtService.generateAccessToken(userDetails);
        LocalDateTime expiration = jwtService.getTokenExpirationAsLocalDateTime(token);

        assertThat(expiration).isAfter(beforeGeneration);
    }

    @Test
    @DisplayName("Should validate token structure successfully")
    void shouldValidateTokenStructureSuccessfully() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        String token = jwtService.generateAccessToken(userDetails);
        boolean isValidStructure = jwtService.validateTokenStructure(token);

        assertThat(isValidStructure).isTrue();
    }

    @Test
    @DisplayName("Should return false for invalid token structure")
    void shouldReturnFalseForInvalidTokenStructure() {
        String invalidToken = "invalid.token.structure";
        boolean isValidStructure = jwtService.validateTokenStructure(invalidToken);

        assertThat(isValidStructure).isFalse();
    }

    @Test
    @DisplayName("Should return false for malformed token")
    void shouldReturnFalseForMalformedToken() {
        String malformedToken = "malformed";
        boolean isValidStructure = jwtService.validateTokenStructure(malformedToken);

        assertThat(isValidStructure).isFalse();
    }

    @Test
    @DisplayName("Should throw JwtException for invalid token when extracting username")
    void shouldThrowJwtExceptionForInvalidTokenWhenExtractingUsername() {
        String invalidToken = "invalid.token.structure";

        assertThrows(JwtException.class, () -> jwtService.extractUsername(invalidToken));
    }

    @Test
    @DisplayName("Should throw JwtException for invalid token when extracting expiration")
    void shouldThrowJwtExceptionForInvalidTokenWhenExtractingExpiration() {
        String invalidToken = "invalid.token.structure";

        assertThrows(JwtException.class, () -> jwtService.extractExpiration(invalidToken));
    }

    @Test
    @DisplayName("Should throw JwtException for invalid token when extracting authorities")
    void shouldThrowJwtExceptionForInvalidTokenWhenExtractingAuthorities() {
        String invalidToken = "invalid.token.structure";

        assertThrows(JwtException.class, () -> jwtService.extractAuthorities(invalidToken));
    }

    @Test
    @DisplayName("Should throw JwtException for invalid token when extracting token type")
    void shouldThrowJwtExceptionForInvalidTokenWhenExtractingTokenType() {
        String invalidToken = "invalid.token.structure";

        assertThrows(JwtException.class, () -> jwtService.extractTokenType(invalidToken));
    }

    @Test
    @DisplayName("Should return true for expired token check with invalid token")
    void shouldReturnTrueForExpiredTokenCheckWithInvalidToken() {
        String invalidToken = "invalid.token.structure";
        boolean isExpired = jwtService.isTokenExpired(invalidToken);

        assertThat(isExpired).isTrue();
    }

    @Test
    @DisplayName("Should return false for access token check with invalid token")
    void shouldReturnFalseForAccessTokenCheckWithInvalidToken() {
        String invalidToken = "invalid.token.structure";
        boolean isAccessToken = jwtService.isAccessToken(invalidToken);

        assertThat(isAccessToken).isFalse();
    }

    @Test
    @DisplayName("Should return false for refresh token check with invalid token")
    void shouldReturnFalseForRefreshTokenCheckWithInvalidToken() {
        String invalidToken = "invalid.token.structure";
        boolean isRefreshToken = jwtService.isRefreshToken(invalidToken);

        assertThat(isRefreshToken).isFalse();
    }

    @Test
    @DisplayName("Should handle empty authorities in access token generation")
    void shouldHandleEmptyAuthoritiesInAccessTokenGeneration() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        String token = jwtService.generateAccessToken(userDetails);
        List<String> extractedAuthorities = jwtService.extractAuthorities(token);

        assertThat(token).isNotNull();
        assertThat(extractedAuthorities).isEmpty();
    }

    @Test
    @DisplayName("Should handle special characters in username")
    void shouldHandleSpecialCharactersInUsername() {
        String username = "user.test-123_special@domain.com";
        when(userDetails.getUsername()).thenReturn(username);
        when(userDetails.getAuthorities()).thenReturn(new ArrayList<>());

        String token = jwtService.generateAccessToken(userDetails);
        String extractedUsername = jwtService.extractUsername(token);

        assertThat(extractedUsername).isEqualTo(username);
    }

    @Test
    @DisplayName("Should validate refresh token has no authorities")
    void shouldValidateRefreshTokenHasNoAuthorities() {
        String username = "testuser";
        when(userDetails.getUsername()).thenReturn(username);

        String token = jwtService.generateRefreshToken(userDetails);
        List<String> extractedAuthorities = jwtService.extractAuthorities(token);

        assertThat(extractedAuthorities).isNull();
    }
}