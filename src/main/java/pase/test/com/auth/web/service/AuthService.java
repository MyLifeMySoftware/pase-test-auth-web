package pase.test.com.auth.web.service;

import java.time.LocalDateTime;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pase.test.com.auth.web.security.UserDetailsServiceImpl;
import pase.test.com.auth.web.security.jwt.JwtService;
import pase.test.com.database.dto.user.AuthResponse;
import pase.test.com.database.dto.user.LoginRequest;
import pase.test.com.database.dto.user.RefreshTokenRequest;
import pase.test.com.database.dto.user.RegisterRequest;
import pase.test.com.database.entity.user.RefreshToken;
import pase.test.com.database.entity.user.Role;
import pase.test.com.database.entity.user.User;
import pase.test.com.database.exception.auth.AuthenticationFailedException;
import pase.test.com.database.exception.auth.InvalidRefreshTokenException;
import pase.test.com.database.exception.auth.UserAlreadyExistsException;
import pase.test.com.database.repository.user.RefreshTokenRepository;
import pase.test.com.database.repository.user.RoleRepository;
import pase.test.com.database.repository.user.UserRepository;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserDetailsServiceImpl userDetailsService;

    /**
     * Authenticate user and generate tokens.
     */
    @Transactional
    public AuthResponse login(LoginRequest request, String ipAddress, String userAgent) {
        try {
            log.info("Attempting authentication for user: {}", request.getUsername());

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            User user = userRepository.findByUsername(request.getUsername())
                    .orElseThrow(() -> new AuthenticationFailedException("User not found"));

            // Update last login
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            // Generate tokens
            String accessToken = jwtService.generateAccessToken(userDetails);
            String refreshToken = jwtService.generateRefreshToken(userDetails);

            // Save refresh token
            saveRefreshToken(user, refreshToken, ipAddress, userAgent);

            log.info("User {} authenticated successfully", request.getUsername());

            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .tokenType("Bearer")
                    .expiresIn(900) // 15 minutes
                    .username(user.getUsername())
                    .email(user.getEmail())
                    .fullName(user.getFullName())
                    .authorities(userDetails.getAuthorities().stream()
                            .map(authority -> authority.getAuthority())
                            .toList())
                    .build();

        } catch (AuthenticationException e) {
            log.error("Authentication failed for user: {}, reason: {}", request.getUsername(), e.getMessage());
            throw new AuthenticationFailedException("Invalid username or password");
        }
    }

    /**
     * Register new user.
     */
    @Transactional
    public AuthResponse register(RegisterRequest request, String ipAddress, String userAgent) {
        log.info("Attempting to register user: {}", request.getUsername());

        // Check if user already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UserAlreadyExistsException("Username already exists");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserAlreadyExistsException("Email already exists");
        }

        // Get default role
        Role defaultRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new RuntimeException("Default role not found"));

        // Create user
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .roles(Set.of(defaultRole))
                .build();

        user = userRepository.save(user);

        // Load user details for token generation
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());

        // Generate tokens
        String accessToken = jwtService.generateAccessToken(userDetails);
        String refreshToken = jwtService.generateRefreshToken(userDetails);

        // Save refresh token
        saveRefreshToken(user, refreshToken, ipAddress, userAgent);

        log.info("User {} registered successfully", request.getUsername());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(900) // 15 minutes
                .username(user.getUsername())
                .email(user.getEmail())
                .fullName(user.getFullName())
                .authorities(userDetails.getAuthorities().stream()
                        .map(authority -> authority.getAuthority())
                        .toList())
                .build();
    }

    /**
     * Refresh access token using refresh token.
     */
    @Transactional
    public AuthResponse refreshToken(RefreshTokenRequest request, String ipAddress, String userAgent) {
        log.info("Attempting to refresh token");

        // Validate refresh token format
        if (!jwtService.validateTokenStructure(request.getRefreshToken())
                || !jwtService.isRefreshToken(request.getRefreshToken())) {
            throw new InvalidRefreshTokenException("Invalid refresh token format");
        }

        // Get refresh token from database
        RefreshToken refreshToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new InvalidRefreshTokenException("Refresh token not found"));

        // Validate refresh token
        if (!refreshToken.isValid()) {
            refreshTokenRepository.delete(refreshToken);
            throw new InvalidRefreshTokenException("Refresh token is expired or revoked");
        }

        // Load user details
        UserDetails userDetails = userDetailsService.loadUserByUsername(refreshToken.getUser().getUsername());

        // Generate new access token
        String newAccessToken = jwtService.generateAccessToken(userDetails);
        String newRefreshToken = jwtService.generateRefreshToken(userDetails);

        // Mark old refresh token as used and save new one
        refreshToken.setUsedAt(LocalDateTime.now());
        refreshToken.setRevoked(true);
        refreshTokenRepository.save(refreshToken);

        saveRefreshToken(refreshToken.getUser(), newRefreshToken, ipAddress, userAgent);

        log.info("Token refreshed successfully for user: {}", refreshToken.getUser().getUsername());

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .tokenType("Bearer")
                .expiresIn(900) // 15 minutes
                .username(refreshToken.getUser().getUsername())
                .email(refreshToken.getUser().getEmail())
                .fullName(refreshToken.getUser().getFullName())
                .authorities(userDetails.getAuthorities().stream()
                        .map(authority -> authority.getAuthority())
                        .toList())
                .build();
    }

    /**
     * Logout user and revoke tokens.
     */
    @Transactional
    public void logout(String refreshToken, String username) {
        log.info("Attempting logout for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        // Revoke specific refresh token if provided
        if (refreshToken != null && !refreshToken.isEmpty()) {
            refreshTokenRepository.revokeToken(refreshToken);
        } else {
            // Revoke all user tokens
            refreshTokenRepository.revokeAllUserTokens(user);
        }

        log.info("User {} logged out successfully", username);
    }

    /**
     * Logout from all devices.
     */
    @Transactional
    public void logoutFromAllDevices(String username) {
        log.info("Attempting logout from all devices for user: {}", username);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BadCredentialsException("User not found"));

        refreshTokenRepository.revokeAllUserTokens(user);

        log.info("User {} logged out from all devices successfully", username);
    }

    /**
     * Save refresh token to database.
     */
    private void saveRefreshToken(User user, String token, String ipAddress, String userAgent) {
        LocalDateTime expiresAt = jwtService.getTokenExpirationAsLocalDateTime(token);

        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .user(user)
                .expiresAt(expiresAt)
                .ipAddress(ipAddress)
                .userAgent(userAgent)
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshToken);
    }

    /**
     * Clean up expired tokens (scheduled task).
     */
    @Transactional
    public void cleanupExpiredTokens() {
        log.info("Cleaning up expired refresh tokens");
        refreshTokenRepository.deleteExpiredTokens(LocalDateTime.now());
    }
}