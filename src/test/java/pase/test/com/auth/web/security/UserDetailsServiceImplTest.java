package pase.test.com.auth.web.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import pase.test.com.database.entity.user.Role;
import pase.test.com.database.entity.user.User;
import pase.test.com.database.entity.user.UserPermission;
import pase.test.com.database.repository.user.UserRepository;

@ExtendWith(MockitoExtension.class)
@DisplayName("User Details Service Implementation Tests")
class UserDetailsServiceImplTest {

    @Mock
    private UserRepository userRepository;

    private UserDetailsServiceImpl userDetailsService;

    @BeforeEach
    void setUp() {
        userDetailsService = new UserDetailsServiceImpl(userRepository);
    }

    @Test
    @DisplayName("Should load user by username successfully")
    void shouldLoadUserByUsernameSuccessfully() {
        String username = "testuser";
        User mockUser = createMockUser(username, "test@example.com", true);

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        UserDetails result = userDetailsService.loadUserByUsername(username);

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo(username);
        assertThat(result.isEnabled()).isTrue();
        assertThat(result.isAccountNonExpired()).isTrue();
        assertThat(result.isAccountNonLocked()).isTrue();
        assertThat(result.isCredentialsNonExpired()).isTrue();

        verify(userRepository).findByUsername(username);
    }

    @Test
    @DisplayName("Should load user with correct authorities")
    void shouldLoadUserWithCorrectAuthorities() {
        String username = "admin";
        User mockUser = createMockUserWithRolesAndPermissions(username);

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        UserDetails result = userDetailsService.loadUserByUsername(username);

        assertThat(result).isNotNull();
        assertThat(result.getAuthorities()).isNotEmpty();

        assertThat(result.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_ADMIN", "ROLE_USER");

        assertThat(result.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("user:read", "user:write", "admin:read");

        verify(userRepository).findByUsername(username);
    }

    @Test
    @DisplayName("Should throw UsernameNotFoundException when user not found")
    void shouldThrowUsernameNotFoundExceptionWhenUserNotFound() {
        String username = "nonexistent";
        when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

        UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> userDetailsService.loadUserByUsername(username)
        );

        assertThat(exception.getMessage())
                .isEqualTo("User not found with username or email: " + username);

        verify(userRepository).findByUsername(username);
    }

    @Test
    @DisplayName("Should handle null username gracefully")
    void shouldHandleNullUsernameGracefully() {
        when(userRepository.findByUsername(null)).thenReturn(Optional.empty());

        UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> userDetailsService.loadUserByUsername(null)
        );

        assertThat(exception.getMessage())
                .isEqualTo("User not found with username or email: null");

        verify(userRepository).findByUsername(null);
    }

    @Test
    @DisplayName("Should handle empty username")
    void shouldHandleEmptyUsername() {

        String emptyUsername = "";
        when(userRepository.findByUsername(emptyUsername)).thenReturn(Optional.empty());


        UsernameNotFoundException exception = assertThrows(
                UsernameNotFoundException.class,
                () -> userDetailsService.loadUserByUsername(emptyUsername)
        );

        assertThat(exception.getMessage())
                .isEqualTo("User not found with username or email: ");

        verify(userRepository).findByUsername(emptyUsername);
    }

    @Test
    @DisplayName("Should load disabled user correctly")
    void shouldLoadDisabledUserCorrectly() {
        String username = "disableduser";
        User mockUser = createMockUser(username, "disabled@example.com", false);

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        UserDetails result = userDetailsService.loadUserByUsername(username);

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo(username);
        assertThat(result.isEnabled()).isFalse();

        verify(userRepository).findByUsername(username);
    }

    @Test
    @DisplayName("Should load user with locked account")
    void shouldLoadUserWithLockedAccount() {
        String username = "lockeduser";
        User mockUser = createMockUser(username, "locked@example.com", true);
        mockUser.setAccountNonLocked(false);

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        UserDetails result = userDetailsService.loadUserByUsername(username);

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo(username);
        assertThat(result.isAccountNonLocked()).isFalse();
        assertThat(result.isEnabled()).isTrue();

        verify(userRepository).findByUsername(username);
    }

    @Test
    @DisplayName("Should load user with expired account")
    void shouldLoadUserWithExpiredAccount() {
        String username = "expireduser";
        User mockUser = createMockUser(username, "expired@example.com", true);
        mockUser.setAccountNonExpired(false);

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        UserDetails result = userDetailsService.loadUserByUsername(username);

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo(username);
        assertThat(result.isAccountNonExpired()).isFalse();

        verify(userRepository).findByUsername(username);
    }

    @Test
    @DisplayName("Should load user with expired credentials")
    void shouldLoadUserWithExpiredCredentials() {
        String username = "expiredcreds";
        User mockUser = createMockUser(username, "expiredcreds@example.com", true);
        mockUser.setCredentialsNonExpired(false);

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        UserDetails result = userDetailsService.loadUserByUsername(username);

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo(username);
        assertThat(result.isCredentialsNonExpired()).isFalse();

        verify(userRepository).findByUsername(username);
    }

    @Test
    @DisplayName("Should load user with no roles")
    void shouldLoadUserWithNoRoles() {
        String username = "noroles";
        User mockUser = createMockUser(username, "noroles@example.com", true);
        mockUser.setRoles(new HashSet<>());

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        UserDetails result = userDetailsService.loadUserByUsername(username);

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo(username);
        assertThat(result.getAuthorities()).isEmpty();

        verify(userRepository).findByUsername(username);
    }

    @Test
    @DisplayName("Should load user with role that has no permissions")
    void shouldLoadUserWithRoleHavingNoPermissions() {
        String username = "emptyrolepermissions";
        User mockUser = createMockUser(username, "empty@example.com", true);

        Role role = Role.builder()
                .id(1L)
                .name("EMPTY_ROLE")
                .description("Role with no permissions")
                .active(true)
                .permissions(new HashSet<>())
                .build();

        mockUser.setRoles(Set.of(role));

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        UserDetails result = userDetailsService.loadUserByUsername(username);

        assertThat(result).isNotNull();
        assertThat(result.getAuthorities()).hasSize(1);
        assertThat(result.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_EMPTY_ROLE");

        verify(userRepository).findByUsername(username);
    }

    @Test
    @DisplayName("Should handle username with special characters")
    void shouldHandleUsernameWithSpecialCharacters() {
        String username = "user.test-123_special";
        User mockUser = createMockUser(username, "special@example.com", true);

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        UserDetails result = userDetailsService.loadUserByUsername(username);

        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo(username);

        verify(userRepository).findByUsername(username);
    }

    @Test
    @DisplayName("Should verify repository is called with exact username")
    void shouldVerifyRepositoryIsCalledWithExactUsername() {
        String username = "ExactUsername";
        User mockUser = createMockUser(username, "exact@example.com", true);

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        userDetailsService.loadUserByUsername(username);

        verify(userRepository).findByUsername(username);
        verify(userRepository).findByUsername(username);
    }

    @Test
    @DisplayName("Should return User object that implements UserDetails")
    void shouldReturnUserObjectThatImplementsUserDetails() {
        String username = "testuser";
        User mockUser = createMockUser(username, "test@example.com", true);

        when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

        UserDetails result = userDetailsService.loadUserByUsername(username);

        assertThat(result).isInstanceOf(User.class);
        assertThat(result).isInstanceOf(UserDetails.class);

        User userResult = (User) result;
        assertThat(userResult.getId()).isEqualTo(mockUser.getId());
        assertThat(userResult.getEmail()).isEqualTo(mockUser.getEmail());
        assertThat(userResult.getFirstName()).isEqualTo(mockUser.getFirstName());
        assertThat(userResult.getLastName()).isEqualTo(mockUser.getLastName());
    }

    private User createMockUser(String username, String email, boolean enabled) {
        return User.builder()
                .id(1L)
                .username(username)
                .email(email)
                .password("encoded_password")
                .firstName("Test")
                .lastName("User")
                .enabled(enabled)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .createdAt(LocalDateTime.now())
                .roles(new HashSet<>())
                .build();
    }

    private User createMockUserWithRolesAndPermissions(String username) {
        UserPermission userReadPerm = UserPermission.builder()
                .id(1L)
                .name("user:read")
                .description("Read user data")
                .resource("user")
                .action("read")
                .active(true)
                .build();

        UserPermission userWritePerm = UserPermission.builder()
                .id(2L)
                .name("user:write")
                .description("Write user data")
                .resource("user")
                .action("write")
                .active(true)
                .build();

        UserPermission adminReadPerm = UserPermission.builder()
                .id(3L)
                .name("admin:read")
                .description("Read admin data")
                .resource("admin")
                .action("read")
                .active(true)
                .build();

        Role userRole = Role.builder()
                .id(1L)
                .name("USER")
                .description("Standard user role")
                .active(true)
                .permissions(Set.of(userReadPerm))
                .build();

        Role adminRole = Role.builder()
                .id(2L)
                .name("ADMIN")
                .description("Administrator role")
                .active(true)
                .permissions(Set.of(userWritePerm, adminReadPerm))
                .build();

        return User.builder()
                .id(1L)
                .username(username)
                .email("admin@example.com")
                .password("encoded_password")
                .firstName("Admin")
                .lastName("User")
                .enabled(true)
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .createdAt(LocalDateTime.now())
                .roles(Set.of(userRole, adminRole))
                .build();
    }
}