package pase.test.com.auth.web.utils;

import java.util.Optional;
import lombok.experimental.UtilityClass;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

@UtilityClass
public class SecurityUtils {

    /**
     * Get current authenticated user
     */
    public static Optional<String> getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return Optional.empty();
        }

        Object principal = authentication.getPrincipal();

        if (principal instanceof UserDetails userDetails) {
            return Optional.of(userDetails.getUsername());
        } else if (principal instanceof String username) {
            return Optional.of(username);
        }

        return Optional.empty();
    }

    /**
     * Get current authentication
     */
    public static Optional<Authentication> getCurrentAuthentication() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return Optional.empty();
        }

        return Optional.of(authentication);
    }

    /**
     * Check if user has specific role
     */
    public static boolean hasRole(String role) {
        return getCurrentAuthentication()
                .map(auth -> auth.getAuthorities().stream()
                        .anyMatch(authority -> authority.getAuthority().equals("ROLE_" + role)))
                .orElse(false);
    }

    /**
     * Check if user has specific authority
     */
    public static boolean hasAuthority(String authority) {
        return getCurrentAuthentication()
                .map(auth -> auth.getAuthorities().stream()
                        .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals(authority)))
                .orElse(false);
    }

    /**
     * Check if current user is authenticated
     */
    public static boolean isAuthenticated() {
        return getCurrentAuthentication().isPresent();
    }
}