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

        initializePermissions();
        initializeRoles();
        initializeUsers();

        log.info("Data initialization completed successfully");
    }

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

    private void initializeRoles() {
        log.info("Initializing roles...");

        // Create USER role with basic permissions
        Role userRole = createRoleIfNotExists("USER", "Standard user role");
        Set<UserPermission> userPermissions = new HashSet<>();
        userPermissions.add(permissionRepository.findByName("user:read").orElse(null));
        userPermissions.add(permissionRepository.findByName("auth:login").orElse(null));
        userPermissions.add(permissionRepository.findByName("auth:logout").orElse(null));
        userPermissions.add(permissionRepository.findByName("auth:refresh").orElse(null));
        userPermissions.removeIf(java.util.Objects::isNull);

        if (!userPermissions.isEmpty()) {
            userRole.setPermissions(userPermissions);
            roleRepository.save(userRole);
            log.info("USER role updated with {} permissions", userPermissions.size());
        }

        // Create ADMIN role with all permissions
        Role adminRole = createRoleIfNotExists("ADMIN", "Administrator role with full access");
        Set<UserPermission> adminPermissions = new HashSet<>(permissionRepository.findAll());
        adminRole.setPermissions(adminPermissions);
        roleRepository.save(adminRole);
        log.info("ADMIN role updated with {} permissions", adminPermissions.size());

        // Create MODERATOR role with moderate permissions
        Role moderatorRole = createRoleIfNotExists("MODERATOR", "Moderator role with limited admin access");
        Set<UserPermission> moderatorPermissions = new HashSet<>();
        moderatorPermissions.add(permissionRepository.findByName("user:read").orElse(null));
        moderatorPermissions.add(permissionRepository.findByName("user:write").orElse(null));
        moderatorPermissions.add(permissionRepository.findByName("role:read").orElse(null));
        moderatorPermissions.add(permissionRepository.findByName("permission:read").orElse(null));
        moderatorPermissions.add(permissionRepository.findByName("auth:login").orElse(null));
        moderatorPermissions.add(permissionRepository.findByName("auth:logout").orElse(null));
        moderatorPermissions.add(permissionRepository.findByName("auth:refresh").orElse(null));
        moderatorPermissions.removeIf(java.util.Objects::isNull);

        if (!moderatorPermissions.isEmpty()) {
            moderatorRole.setPermissions(moderatorPermissions);
            roleRepository.save(moderatorRole);
            log.info("MODERATOR role updated with {} permissions", moderatorPermissions.size());
        }

        log.info("Roles initialized successfully");
    }

    private void initializeUsers() {
        log.info("Initializing users...");

        // Create admin user
        if (!userRepository.existsByUsername("admin")) {
            Role adminRole = roleRepository.findByName("ADMIN").orElse(null);
            if (adminRole != null) {
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
                log.info("Admin user created successfully with role: {}", adminRole.getName());
            } else {
                log.error("ADMIN role not found, cannot create admin user");
            }
        }

        // Create test user
        if (!userRepository.existsByUsername("testuser")) {
            Role userRole = roleRepository.findByName("USER").orElse(null);
            if (userRole != null) {
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
                log.info("Test user created successfully with role: {}", userRole.getName());
            } else {
                log.error("USER role not found, cannot create test user");
            }
        }

        // create moderator user
        if (!userRepository.existsByUsername("moderator")) {
            Role userRole = roleRepository.findByName("MODERATOR").orElse(null);
            if (userRole != null) {
                Set<Role> userRoles = new HashSet<>();
                userRoles.add(userRole);

                User testUser = User.builder()
                        .username("moderator")
                        .email("moderator@pase.com")
                        .password(passwordEncoder.encode("Mod123!"))
                        .firstName("Moderator")
                        .lastName("Dummy")
                        .enabled(true)
                        .accountNonExpired(true)
                        .accountNonLocked(true)
                        .credentialsNonExpired(true)
                        .roles(userRoles)
                        .build();

                userRepository.save(testUser);
                log.info("Test user created successfully with role: {}", userRole.getName());
            } else {
                log.error("USER role not found, cannot create test user");
            }
        }

        log.info("Users initialized successfully");
    }

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
        } else {
            log.debug("Permission already exists: {}", name);
        }
    }

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