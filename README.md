# 🔐 Sistema de Autenticación JWT - Pase Project

Sistema de autenticación empresarial robusto con JWT para microservicios usando Spring Boot 3.3.13 y Java 21.

## 🏗️ Arquitectura del Sistema

```
┌─────────────────────────────────────────────────────────────┐
│                   Pase Authentication System                │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐    ┌─────────────────────────────┐  │
│  │ pase-test-auth-web  │    │  pase-test-database-lib     │  │
│  │                     │    │                             │  │
│  │ • REST API          │◄───┤ • JPA Entities             │  │
│  │ • JWT Security      │    │ • Repositories              │  │
│  │ • Controllers       │    │ • DTOs                      │  │
│  │ • Business Logic    │    │ • Exceptions                │  │
│  └─────────────────────┘    └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Módulos

- **pase-test-database-lib**: Librería compartida con entidades JPA, repositorios y DTOs
- **pase-test-auth-web**: Microservicio de autenticación con API REST y lógica de negocio

## ✨ Características Principales

| Característica | Implementado | Descripción |
|---|:---:|---|
| **JWT Authentication** | ✅ | Access tokens (15 min) y refresh tokens (7 días) |
| **Role-Based Access** | ✅ | Sistema de roles granulares con permisos |
| **Seguridad Robusta** | ✅ | BCrypt, validación de entrada, CORS |
| **Gestión de Tokens** | ✅ | Revocación, limpieza automática, múltiples dispositivos |
| **Validación Avanzada** | ✅ | Spring Validation con patrones personalizados |
| **Manejo de Excepciones** | ✅ | Global exception handler con respuestas estructuradas |
| **Monitoreo** | ✅ | Actuator, métricas personalizadas, health checks |
| **Documentación API** | ✅ | OpenAPI 3.0 con Swagger UI |
| **Multi-perfil** | ✅ | Configuraciones para dev, test, prod |

## 🛠️ Stack Tecnológico

### Backend Core
- **Java 21** - Última versión LTS
- **Spring Boot 3.3.13** - Framework principal
- **Spring Security 6** - Seguridad y autenticación
- **Spring Data JPA** - Persistencia de datos
- **Hibernate** - ORM con soporte Envers

### Seguridad y JWT
- **JJWT 0.12.5** - Librería JWT robusta
- **BCrypt** - Encriptación de contraseñas
- **Spring Security** - Configuración de seguridad

### Base de Datos
- **PostgreSQL** - Base de datos principal
- **HikariCP** - Pool de conexiones optimizado
- **Spring Data Envers** - Auditoría de cambios

### Herramientas de Desarrollo
- **Lombok** - Reducción de boilerplate
- **MapStruct** - Mapeo de objetos
- **Micrometer** - Métricas y observabilidad
- **Checkstyle** - Calidad de código

## 🚀 Instalación y Configuración

### Prerrequisitos
```bash
Java 21+
Maven 3.8+
PostgreSQL 12+
```

### 1. Clonar el repositorio
```bash
git clone https://github.com/MyLifeMySoftware/pase-test-auth-web
cd pase-project
```

### 2. Configurar Base de Datos
```sql
-- Crear base de datos
CREATE DATABASE pase_db;
CREATE USER owner WITH ENCRYPTED PASSWORD 'Owner123';
GRANT ALL PRIVILEGES ON DATABASE pase_db TO owner;
```

### 3. Variables de Entorno
```bash
# Crear archivo .env
cat > .env << EOF
# Database Configuration
DB_URL=jdbc:postgresql://localhost:5432/pase_db
DB_USERNAME=owner
DB_PASSWORD=Owner123

# JWT Configuration
JWT_SECRET=404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970
JWT_ACCESS_TOKEN_EXPIRATION=900000
JWT_REFRESH_TOKEN_EXPIRATION=604800000
JWT_ISSUER=pase-auth-service

# Application Configuration
SPRING_PROFILES_ACTIVE=dev
SERVER_PORT=8080
EOF
```

### 4. Compilar e Instalar
```bash
# Instalar librería de base de datos
cd pase-test-database-lib
mvn clean install

# Compilar microservicio de autenticación
cd ../pase-test-auth-web
mvn clean install
```

## 🔐 Configuración de Seguridad

### JWT Configuration
```yaml
jwt:
  secret: ${JWT_SECRET:404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970}
  access-token:
    expiration: ${JWT_ACCESS_TOKEN_EXPIRATION:900000}  # 15 minutos
  refresh-token:
    expiration: ${JWT_REFRESH_TOKEN_EXPIRATION:604800000}  # 7 días
  issuer: ${JWT_ISSUER:pase-auth-service}
```

### Usuarios por Defecto
```yaml
# Usuarios creados automáticamente en el primer arranque
Admin:
  username: admin
  password: Admin123!
  role: ADMIN
  
Test User:
  username: testuser  
  password: Test123!
  role: USER
  
Moderator:
  username: moderator
  password: Mod123!
  role: MODERATOR
```

## 📚 API Documentation

### Base URL
```
http://localhost:8080/swagger-ui/index.html#/
```

### Endpoints Principales

#### 🔓 Endpoints Públicos

| Método | Endpoint | Descripción |
|--------|----------|-------------|
| `POST` | `/register` | Registro de nuevo usuario |
| `POST` | `/login` | Autenticación de usuario |
| `POST` | `/refresh` | Renovar access token |
| `GET` | `/health` | Health check del servicio |

#### 🔒 Endpoints Protegidos

| Método | Endpoint | Permisos | Descripción |
|--------|----------|----------|-------------|
| `POST` | `/logout` | USER | Cerrar sesión |
| `GET` | `/profile` | USER | Obtener perfil del usuario |
| `POST` | `/validate` | USER | Validar token actual |

### Ejemplos de Uso

#### 1. Registro de Usuario
```bash
curl -X POST http://localhost:8080/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "email": "newuser@example.com",
    "password": "NewUser123!",
    "firstName": "New",
    "lastName": "User"
  }'
```

**Respuesta:**
```json
{
  "success": true,
  "message": "Registration successful",
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "tokenType": "Bearer",
    "expiresIn": 900,
    "username": "newuser",
    "email": "newuser@example.com",
    "fullName": "New User",
    "authorities": ["user:read", "auth:login", "auth:logout", "auth:refresh"]
  },
  "timestamp": "2025-01-15T10:30:00"
}
```

#### 2. Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "Test123!"
  }'
```

#### 3. Acceso a Endpoint Protegido
```bash
curl -X GET http://localhost:8080/api/v1/auth/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

#### 4. Refresh Token
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN"
  }'
```

#### 5. Logout
```bash
curl -X POST http://localhost:8080/api/v1/auth/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN",
    "logoutFromAllDevices": false
  }'
```

## 🔧 Integración con Microservicios

### 1. Agregar Dependencia
```xml
<dependency>
    <groupId>pase.test.com</groupId>
    <artifactId>pase-test-database-lib</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>

<dependency>
    <groupId>pase.test.com</groupId>
    <artifactId>pase-test-auth-web</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

### 2. Configurar JWT Filter
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Autowired
    private JwtAuthenticationFilter jwtAuthFilter;
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }
}
```

### 3. Usar Información del Usuario
```java
@RestController
public class ProtectedController {
    
    @GetMapping("/api/protected")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<String> protectedEndpoint(Authentication auth) {
        String username = auth.getName();
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        
        return ResponseEntity.ok("Hello " + username + "!");
    }
}
```

## 🧪 Testing

### Ejecutar Tests
```bash
# Tests unitarios
mvn test

# Tests de integración
mvn test -Dspring.profiles.active=test

# Tests con coverage
mvn clean test jacoco:report
```

### Test de Endpoints
```bash
# Verificar salud del servicio
curl http://localhost:8080/api/v1/auth/health

# Verificar documentación
curl http://localhost:8080/v3/api-docs

# Acceder a Swagger UI
open http://localhost:8080/swagger-ui/index.html
```

## 📊 Monitoreo y Observabilidad

### Actuator Endpoints
```bash
# Health check
GET /actuator/health

# Información de la aplicación
GET /actuator/info

# Métricas generales
GET /actuator/metrics

# Métricas específicas
GET /actuator/metrics/auth.login
GET /actuator/metrics/auth.register
GET /actuator/metrics/auth.refresh

# Prometheus metrics
GET /actuator/prometheus
```

### Métricas Personalizadas
- `auth.login` - Tiempo de procesamiento de login
- `auth.register` - Tiempo de procesamiento de registro
- `auth.refresh` - Tiempo de procesamiento de refresh token
- `auth.logout` - Tiempo de procesamiento de logout

```

## 🔒 Seguridad Implementada

### Autenticación JWT
- **Access Tokens**: 15 minutos de duración
- **Refresh Tokens**: 7 días de duración, almacenados en BD
- **Token Revocation**: Posibilidad de revocar tokens específicos
- **Multi-device**: Soporte para múltiples dispositivos simultáneos

### Validación de Entrada
```java
@NotBlank(message = "Username is required")
@Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
@Pattern(regexp = "^[a-zA-Z0-9._-]+$", message = "Username can only contain letters, numbers, dots, underscores, and hyphens")
private String username;

@NotBlank(message = "Password is required")
@Size(min = 8, max = 128, message = "Password must be between 8 and 128 characters")
@Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]+$",
        message = "Password must contain at least one lowercase letter, one uppercase letter, one digit, and one special character")
private String password;
```

### Configuración CORS
```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.setAllowedOriginPatterns(Arrays.asList("*"));
    configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
    configuration.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type", "X-Requested-With"));
    configuration.setAllowCredentials(true);
    configuration.setMaxAge(3600L);
    
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

## 📁 Estructura del Proyecto

```
pase-project/
├── pase-test-database-lib/              # Librería compartida
│   ├── src/main/java/
│   │   └── pase/test/com/database/
│   │       ├── entity/                  # Entidades JPA
│   │       │   └── user/
│   │       │       ├── User.java
│   │       │       ├── Role.java
│   │       │       ├── UserPermission.java
│   │       │       └── RefreshToken.java
│   │       ├── repository/              # Repositorios JPA
│   │       │   └── user/
│   │       ├── dto/                     # Data Transfer Objects
│   │       │   └── user/
│   │       ├── exception/               # Excepciones personalizadas
│   │       └── config/                  # Configuraciones
│   └── pom.xml
│
├── pase-test-auth-web/                  # Microservicio de autenticación
│   ├── src/main/java/
│   │   └── pase/test/com/auth/web/
│   │       ├── controller/              # Controllers REST
│   │       │   └── AuthController.java
│   │       ├── service/                 # Lógica de negocio
│   │       │   └── AuthService.java
│   │       ├── security/                # Configuración de seguridad
│   │       │   ├── SecurityConfig.java
│   │       │   ├── UserDetailsServiceImpl.java
│   │       │   └── jwt/
│   │       │       ├── JwtService.java
│   │       │       ├── JwtAuthenticationFilter.java
│   │       │       └── JwtAuthenticationEntryPoint.java
│   │       ├── config/                  # Configuraciones
│   │       ├── utils/                   # Utilidades
│   │       └── boot/                    # Inicialización
│   │           └── DataInitializationService.java
│   ├── src/main/resources/
│   │   ├── application.properties
│   │   └── application.yml
│   └── pom.xml
│
└── README.md
```

## 🐛 Troubleshooting

### Problemas Comunes

#### Error de Compilación
```bash
# Error: "Association targets java.security.Permission"
# Solución: Limpiar y recompilar
mvn clean install -DskipTests
```

#### Error de JWT
```bash
# Error: "JWT token expired"
# Verificar configuración
jwt.access-token.expiration=900000  # 15 minutos
jwt.refresh-token.expiration=604800000  # 7 días
```

#### Error de Base de Datos
```bash
# Error: "User not found"
# Verificar inicialización de datos
spring.jpa.hibernate.ddl-auto=update
```

#### Error de Conexión
```bash
# Error: "Connection refused"
# Verificar PostgreSQL
systemctl status postgresql
systemctl start postgresql
```

### Logs de Debugging
```bash
# Habilitar debug logging
logging.level.pase.test.com=DEBUG
logging.level.org.springframework.security=DEBUG

# Ver logs en tiempo real
tail -f logs/auth-service.log
```

## 🤝 Contribución

### Proceso de Contribución
1. **Fork** el repositorio
2. **Crear** branch de feature: `git checkout -b feature/amazing-feature`
3. **Commit** cambios: `git commit -m 'Add amazing feature'`
4. **Push** al branch: `git push origin feature/amazing-feature`
5. **Abrir** Pull Request

### Estándares de Código
- Seguir las convenciones de Google Java Style
- Usar Checkstyle para validación
- Mantener coverage de tests > 80%
- Documentar APIs con OpenAPI

### Equipo de Desarrollo
- **Lead Developer**: Erick Antonio Reyes Montalvo
- **Email**: montalvoerickantonio@gmail.com
- **GitHub**: [@ErickReyesMontalvo](https://github.com/ErickReyesMontalvo)

---

<div align="center">
  <p>Hecho con ❤️</p>
  <p>
    <a href="#-sistema-de-autenticación-jwt---pase-project">⬆ Volver al inicio</a>
  </p>
</div>
