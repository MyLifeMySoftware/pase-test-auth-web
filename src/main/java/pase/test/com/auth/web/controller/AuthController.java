package pase.test.com.auth.web.controller;

import io.micrometer.core.annotation.Timed;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pase.test.com.auth.web.service.AuthService;
import pase.test.com.auth.web.utils.HttpUtils;
import pase.test.com.database.dto.ApiResponse;
import pase.test.com.database.dto.user.AuthResponse;
import pase.test.com.database.dto.user.LoginRequest;
import pase.test.com.database.dto.user.LogoutRequest;
import pase.test.com.database.dto.user.RefreshTokenRequest;
import pase.test.com.database.dto.user.RegisterRequest;

@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * User login endpoint
     */
    @PostMapping("/login")
    @Timed(value = "auth.login", description = "Time taken to process login")
    public ResponseEntity<ApiResponse<AuthResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {

        log.info("Login attempt for user: {}", request.getUsername());

        String ipAddress = HttpUtils.getClientIpAddress(httpRequest);
        String userAgent = HttpUtils.getUserAgent(httpRequest);

        AuthResponse authResponse = authService.login(request, ipAddress, userAgent);

        return ResponseEntity.ok(ApiResponse.success("Login successful", authResponse));
    }

    /**
     * User registration endpoint
     */
    @PostMapping("/register")
    @Timed(value = "auth.register", description = "Time taken to process registration")
    public ResponseEntity<ApiResponse<AuthResponse>> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest httpRequest) {

        log.info("Registration attempt for user: {}", request.getUsername());

        String ipAddress = HttpUtils.getClientIpAddress(httpRequest);
        String userAgent = HttpUtils.getUserAgent(httpRequest);

        AuthResponse authResponse = authService.register(request, ipAddress, userAgent);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(ApiResponse.success("Registration successful", authResponse));
    }

    /**
     * Refresh token endpoint
     */
    @PostMapping("/refresh")
    @Timed(value = "auth.refresh", description = "Time taken to refresh token")
    public ResponseEntity<ApiResponse<AuthResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request,
            HttpServletRequest httpRequest) {

        log.info("Token refresh attempt");

        String ipAddress = HttpUtils.getClientIpAddress(httpRequest);
        String userAgent = HttpUtils.getUserAgent(httpRequest);

        AuthResponse authResponse = authService.refreshToken(request, ipAddress, userAgent);

        return ResponseEntity.ok(ApiResponse.success("Token refreshed successfully", authResponse));
    }

    /**
     * User logout endpoint
     */
    @PostMapping("/logout")
    @PreAuthorize("hasRole('USER')")
    @Timed(value = "auth.logout", description = "Time taken to process logout")
    public ResponseEntity<ApiResponse<Void>> logout(@RequestBody(required = false) LogoutRequest request) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();

        log.info("Logout attempt for user: {}", username);

        if (request != null && request.isLogoutFromAllDevices()) {
            authService.logoutFromAllDevices(username);
            return ResponseEntity.ok(ApiResponse.success("Logged out from all devices successfully", null));
        } else {
            String refreshToken = request != null ? request.getRefreshToken() : null;
            authService.logout(refreshToken, username);
            return ResponseEntity.ok(ApiResponse.success("Logout successful", null));
        }
    }

    /**
     * Get current user profile
     */
    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    @Timed(value = "auth.profile", description = "Time taken to get user profile")
    public ResponseEntity<ApiResponse<Object>> getProfile() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Object profileData = Map.of(
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities(),
                "authenticated", authentication.isAuthenticated()
        );

        return ResponseEntity.ok(ApiResponse.success("Profile retrieved successfully", profileData));
    }

    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    public ResponseEntity<ApiResponse<String>> health() {
        return ResponseEntity.ok(ApiResponse.success("Auth service is running", "OK"));
    }

    /**
     * Validate token endpoint
     */
    @PostMapping("/validate")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ApiResponse<Object>> validateToken() {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        Object validationData = Map.of(
                "valid", true,
                "username", authentication.getName(),
                "authorities", authentication.getAuthorities()
        );

        return ResponseEntity.ok(ApiResponse.success("Token is valid", validationData));
    }
}