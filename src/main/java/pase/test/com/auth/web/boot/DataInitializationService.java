package pase.test.com.auth.web.boot;

import java.util.HashSet;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pase.test.com.database.entity.user.Role;
import pase.test.com.database.entity.user.User;
import pase.test.com.database.entity.user.UserPermission;
import pase.test.com.database.repository.user.PermissionRepository;
import pase.test.com.database.repository.user.RoleRepository;
import pase.test.com.database.repository.user.UserRepository;

@Slf4j
@Service
@RequiredArgsConstructor
public class DataInitializationService implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        log.info("Starting data initialization...");

        //initializePermissions();
        //initializeRoles();
        //initializeUsers();

        log.info("Data initialization completed successfully");
    }

    /**
     * Initialize default permissions
     */
    private void initializePermissions() {
        log.info("Initializing permissions...");

        // User permissions
        createPermissionIfNotExists("user:read", "Read user information", "user", "read");
        createPermissionIfNotExists("user:write", "Write user information", "user", "write");
        createPermissionIfNotExists("user:delete", "Delete user", "user", "delete");

        // Role permissions
        createPermissionIfNotExists("role:read", "Read role information", "role", "read");
        createPermissionIfNotExists("role:write", "Write role information", "role", "write");
        createPermissionIfNotExists("role:delete", "Delete role", "role", "delete");

        // Permission permissions
        createPermissionIfNotExists("permission:read", "Read permission information", "permission", "read");
        createPermissionIfNotExists("permission:write", "Write permission information", "permission", "write");
        createPermissionIfNotExists("permission:delete", "Delete permission", "permission", "delete");

        // Auth permissions
        createPermissionIfNotExists("auth:login", "Login to system", "auth", "login");
        createPermissionIfNotExists("auth:logout", "Logout from system", "auth", "logout");
        createPermissionIfNotExists("auth:refresh", "Refresh token", "auth", "refresh");

        // Admin permissions
        createPermissionIfNotExists("admin:read", "Read admin information", "admin", "read");
        createPermissionIfNotExists("admin:write", "Write admin information", "admin", "write");
        createPermissionIfNotExists("admin:delete", "Delete admin resources", "admin", "delete");

        log.info("Permissions initialized successfully");
    }

    /**
     * Initialize default roles
     */
    private void initializeRoles() {
        log.info("Initializing roles...");

        // Create USER role with basic permissions
        Role userRole = createRoleIfNotExists("USER", "Standard user role");
        if (userRole.getPermissions() == null || userRole.getPermissions().isEmpty()) {
            Set<UserPermission> userPermissions = new HashSet<>();
            userPermissions.add(permissionRepository.findByName("user:read").orElseThrow());
            userPermissions.add(permissionRepository.findByName("auth:login").orElseThrow());
            userPermissions.add(permissionRepository.findByName("auth:logout").orElseThrow());
            userPermissions.add(permissionRepository.findByName("auth:refresh").orElseThrow());
            userRole.setPermissions(userPermissions);
            roleRepository.save(userRole);
        }

        // Create ADMIN role with all permissions
        Role adminRole = createRoleIfNotExists("ADMIN", "Administrator role with full access");
        if (adminRole.getPermissions() == null || adminRole.getPermissions().isEmpty()) {
            Set<UserPermission> adminPermissions = new HashSet<>(permissionRepository.findAll());
            adminRole.setPermissions(adminPermissions);
            roleRepository.save(adminRole);
        }

        // Create MODERATOR role with moderate permissions
        Role moderatorRole = createRoleIfNotExists("MODERATOR", "Moderator role with limited admin access");
        if (moderatorRole.getPermissions() == null || moderatorRole.getPermissions().isEmpty()) {
            Set<UserPermission> moderatorPermissions = new HashSet<>();
            moderatorPermissions.add(permissionRepository.findByName("user:read").orElseThrow());
            moderatorPermissions.add(permissionRepository.findByName("user:write").orElseThrow());
            moderatorPermissions.add(permissionRepository.findByName("role:read").orElseThrow());
            moderatorPermissions.add(permissionRepository.findByName("permission:read").orElseThrow());
            moderatorPermissions.add(permissionRepository.findByName("auth:login").orElseThrow());
            moderatorPermissions.add(permissionRepository.findByName("auth:logout").orElseThrow());
            moderatorPermissions.add(permissionRepository.findByName("auth:refresh").orElseThrow());
            moderatorRole.setPermissions(moderatorPermissions);
            roleRepository.save(moderatorRole);
        }

        log.info("Roles initialized successfully");
    }

    /**
     * Initialize default users
     */
    private void initializeUsers() {
        log.info("Initializing users...");

        // Create admin user
        if (!userRepository.existsByUsername("admin")) {
            Role adminRole = roleRepository.findByName("ADMIN").orElseThrow();

            Set<Role> adminRoles = new HashSet<>();
            adminRoles.add(adminRole);

            User admin = User.builder()
                    .username("admin")
                    .email("admin@pase.com")
                    .password(passwordEncoder.encode("Admin123!"))
                    .firstName("System")
                    .lastName("Administrator")
                    .enabled(true)
                    .accountNonExpired(true)
                    .accountNonLocked(true)
                    .credentialsNonExpired(true)
                    .roles(adminRoles)
                    .build();

            userRepository.save(admin);
            log.info("Admin user created successfully");
        }

        // Create test user
        if (!userRepository.existsByUsername("testuser")) {
            Role userRole = roleRepository.findByName("USER").orElseThrow();

            Set<Role> userRoles = new HashSet<>();
            userRoles.add(userRole);

            User testUser = User.builder()
                    .username("testuser")
                    .email("test@pase.com")
                    .password(passwordEncoder.encode("Test123!"))
                    .firstName("Test")
                    .lastName("User")
                    .enabled(true)
                    .accountNonExpired(true)
                    .accountNonLocked(true)
                    .credentialsNonExpired(true)
                    .roles(userRoles)
                    .build();

            userRepository.save(testUser);
            log.info("Test user created successfully");
        }

        // Create moderator user
        if (!userRepository.existsByUsername("moderator")) {
            Role moderatorRole = roleRepository.findByName("MODERATOR").orElseThrow();

            Set<Role> moderatorRoles = new HashSet<>();
            moderatorRoles.add(moderatorRole);

            User moderator = User.builder()
                    .username("moderator")
                    .email("moderator@pase.com")
                    .password(passwordEncoder.encode("Mod123!"))
                    .firstName("System")
                    .lastName("Moderator")
                    .enabled(true)
                    .accountNonExpired(true)
                    .accountNonLocked(true)
                    .credentialsNonExpired(true)
                    .roles(moderatorRoles)
                    .build();

            userRepository.save(moderator);
            log.info("Moderator user created successfully");
        }

        log.info("Users initialized successfully");
    }

    /**
     * Create permission if it doesn't exist
     */
    private void createPermissionIfNotExists(String name, String description, String resource, String action) {
        if (!permissionRepository.existsByName(name)) {
            UserPermission permission = UserPermission.builder()
                    .name(name)
                    .description(description)
                    .resource(resource)
                    .action(action)
                    .active(true)
                    .build();

            permissionRepository.save(permission);
            log.debug("Created permission: {}", name);
        }
    }

    /**
     * Create role if it doesn't exist
     */
    private Role createRoleIfNotExists(String name, String description) {
        return roleRepository.findByName(name).orElseGet(() -> {
            Role role = Role.builder()
                    .name(name)
                    .description(description)
                    .active(true)
                    .build();

            Role savedRole = roleRepository.save(role);
            log.debug("Created role: {}", name);
            return savedRole;
        });
    }
}