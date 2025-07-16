package pase.test.com.auth.web.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import pase.test.com.database.dto.ErrorResponse;

@ExtendWith(MockitoExtension.class)
@DisplayName("JWT Authentication Entry Point Tests")
class JwtAuthenticationEntryPointTest {

    @Mock
    private ObjectMapper objectMapper;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private AuthenticationException authException;

    private JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @BeforeEach
    void setUp() {
        jwtAuthenticationEntryPoint = new JwtAuthenticationEntryPoint(objectMapper);
    }

    @Test
    @DisplayName("Should handle authentication exception successfully")
    void shouldHandleAuthenticationExceptionSuccessfully() throws IOException, ServletException {
        String requestUri = "/api/v1/auth/profile";
        String exceptionMessage = "Access denied";

        when(request.getRequestURI()).thenReturn(requestUri);
        when(authException.getMessage()).thenReturn(exceptionMessage);

        jwtAuthenticationEntryPoint.commence(request, response, authException);

        verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        ArgumentCaptor<ErrorResponse> errorResponseCaptor = ArgumentCaptor.forClass(ErrorResponse.class);
        verify(objectMapper).writeValue(eq(response.getOutputStream()), errorResponseCaptor.capture());

        ErrorResponse capturedErrorResponse = errorResponseCaptor.getValue();
        assertThat(capturedErrorResponse.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(capturedErrorResponse.getError()).isEqualTo("Unauthorized");
        assertThat(capturedErrorResponse.getMessage())
                .isEqualTo("Full authentication is required to access this resource");
        assertThat(capturedErrorResponse.getPath()).isEqualTo(requestUri);
        assertThat(capturedErrorResponse.getTimestamp()).isNotNull();
    }

    @Test
    @DisplayName("Should handle different request URIs correctly")
    void shouldHandleDifferentRequestUrisCorrectly() throws IOException, ServletException {
        String requestUri = "/api/v1/orders/create";

        when(request.getRequestURI()).thenReturn(requestUri);
        when(authException.getMessage()).thenReturn("Token expired");

        jwtAuthenticationEntryPoint.commence(request, response, authException);

        ArgumentCaptor<ErrorResponse> errorResponseCaptor = ArgumentCaptor.forClass(ErrorResponse.class);
        verify(objectMapper).writeValue(eq(response.getOutputStream()), errorResponseCaptor.capture());

        ErrorResponse capturedErrorResponse = errorResponseCaptor.getValue();
        assertThat(capturedErrorResponse.getPath()).isEqualTo(requestUri);
    }

    @Test
    @DisplayName("Should handle null request URI")
    void shouldHandleNullRequestUri() throws IOException, ServletException {
        when(request.getRequestURI()).thenReturn(null);
        when(authException.getMessage()).thenReturn("Authentication required");

        jwtAuthenticationEntryPoint.commence(request, response, authException);

        ArgumentCaptor<ErrorResponse> errorResponseCaptor = ArgumentCaptor.forClass(ErrorResponse.class);
        verify(objectMapper).writeValue(eq(response.getOutputStream()), errorResponseCaptor.capture());

        ErrorResponse capturedErrorResponse = errorResponseCaptor.getValue();
        assertThat(capturedErrorResponse.getPath()).isNull();
    }

    @Test
    @DisplayName("Should handle empty request URI")
    void shouldHandleEmptyRequestUri() throws IOException, ServletException {
        String emptyUri = "";

        when(request.getRequestURI()).thenReturn(emptyUri);
        when(authException.getMessage()).thenReturn("No token provided");

        jwtAuthenticationEntryPoint.commence(request, response, authException);

        ArgumentCaptor<ErrorResponse> errorResponseCaptor = ArgumentCaptor.forClass(ErrorResponse.class);
        verify(objectMapper).writeValue(eq(response.getOutputStream()), errorResponseCaptor.capture());

        ErrorResponse capturedErrorResponse = errorResponseCaptor.getValue();
        assertThat(capturedErrorResponse.getPath()).isEqualTo(emptyUri);
    }

    @Test
    @DisplayName("Should handle different authentication exception types")
    void shouldHandleDifferentAuthenticationExceptionTypes() throws IOException, ServletException {
        BadCredentialsException badCredentialsException = new BadCredentialsException("Invalid credentials");
        String requestUri = "/api/v1/management/users";

        when(request.getRequestURI()).thenReturn(requestUri);

        jwtAuthenticationEntryPoint.commence(request, response, badCredentialsException);

        verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        ArgumentCaptor<ErrorResponse> errorResponseCaptor = ArgumentCaptor.forClass(ErrorResponse.class);
        verify(objectMapper).writeValue(eq(response.getOutputStream()), errorResponseCaptor.capture());

        ErrorResponse capturedErrorResponse = errorResponseCaptor.getValue();
        assertThat(capturedErrorResponse.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(capturedErrorResponse.getError()).isEqualTo("Unauthorized");
    }

    @Test
    @DisplayName("Should handle null AuthenticationException message")
    void shouldHandleNullAuthenticationExceptionMessage() throws IOException, ServletException {
        String requestUri = "/api/v1/protected";

        when(request.getRequestURI()).thenReturn(requestUri);
        when(authException.getMessage()).thenReturn(null);

        jwtAuthenticationEntryPoint.commence(request, response, authException);

        verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        ArgumentCaptor<ErrorResponse> errorResponseCaptor = ArgumentCaptor.forClass(ErrorResponse.class);
        verify(objectMapper).writeValue(eq(response.getOutputStream()), errorResponseCaptor.capture());

        ErrorResponse capturedErrorResponse = errorResponseCaptor.getValue();
        assertThat(capturedErrorResponse.getStatus()).isEqualTo(HttpServletResponse.SC_UNAUTHORIZED);
        assertThat(capturedErrorResponse.getError()).isEqualTo("Unauthorized");
        assertThat(capturedErrorResponse.getMessage())
                .isEqualTo("Full authentication is required to access this resource");
    }

    @Test
    @DisplayName("Should verify response content type and status are set correctly")
    void shouldVerifyResponseContentTypeAndStatus() throws IOException, ServletException {
        when(request.getRequestURI()).thenReturn("/test");
        when(authException.getMessage()).thenReturn("Test exception");

        jwtAuthenticationEntryPoint.commence(request, response, authException);

        verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        var inOrder = org.mockito.Mockito.inOrder(response, objectMapper);
        inOrder.verify(response).setContentType(MediaType.APPLICATION_JSON_VALUE);
        inOrder.verify(response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        inOrder.verify(objectMapper).writeValue(eq(response.getOutputStream()), any(ErrorResponse.class));
    }

    @Test
    @DisplayName("Should create ErrorResponse with correct structure")
    void shouldCreateErrorResponseWithCorrectStructure() throws IOException, ServletException {
        String requestUri = "/api/v1/auth/validate";
        String exceptionMessage = "JWT token is invalid";

        when(request.getRequestURI()).thenReturn(requestUri);
        when(authException.getMessage()).thenReturn(exceptionMessage);

        jwtAuthenticationEntryPoint.commence(request, response, authException);

        ArgumentCaptor<ErrorResponse> errorResponseCaptor = ArgumentCaptor.forClass(ErrorResponse.class);
        verify(objectMapper).writeValue(eq(response.getOutputStream()), errorResponseCaptor.capture());

        ErrorResponse errorResponse = errorResponseCaptor.getValue();

        assertThat(errorResponse.getStatus()).isEqualTo(401);
        assertThat(errorResponse.getError()).isEqualTo("Unauthorized");
        assertThat(errorResponse.getMessage())
                .isEqualTo("Full authentication is required to access this resource");
        assertThat(errorResponse.getPath()).isEqualTo(requestUri);
        assertThat(errorResponse.getTimestamp()).isNotNull();

        assertThat(errorResponse.getTimestamp())
                .isAfter(java.time.LocalDateTime.now().minusSeconds(5))
                .isBefore(java.time.LocalDateTime.now().plusSeconds(1));
    }

    @Test
    @DisplayName("Should handle various URI patterns")
    void shouldHandleVariousUriPatterns() throws IOException, ServletException {
        String[] testUris = {
                "/api/v1/auth/profile",
                "/api/v1/management/users/123",
                "/api/v1/orders",
                "/actuator/health",
                "/swagger-ui/index.html",
                "/very/long/path/with/many/segments/and/id/12345"
        };

        for (String uri : testUris) {
            when(request.getRequestURI()).thenReturn(uri);
            when(authException.getMessage()).thenReturn("Access denied for " + uri);

            jwtAuthenticationEntryPoint.commence(request, response, authException);

            ArgumentCaptor<ErrorResponse> errorResponseCaptor = ArgumentCaptor.forClass(ErrorResponse.class);
            verify(objectMapper).writeValue(eq(response.getOutputStream()), errorResponseCaptor.capture());

            ErrorResponse errorResponse = errorResponseCaptor.getValue();
            assertThat(errorResponse.getPath()).isEqualTo(uri);

            org.mockito.Mockito.reset(objectMapper);
        }
    }
}