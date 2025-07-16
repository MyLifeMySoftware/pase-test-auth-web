package pase.test.com.auth.web.utils;

import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;

@UtilityClass
public class HttpUtils {

    private static final String[] IP_HEADER_NAMES = {
            "X-Forwarded-For",
            "X-Real-IP",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_FORWARDED",
            "HTTP_VIA",
            "REMOTE_ADDR"
    };

    /**
     * Get client IP address from HTTP request.
     */
    public static String getClientIpAddress(HttpServletRequest request) {
        for (String header : IP_HEADER_NAMES) {
            String ipAddress = request.getHeader(header);
            if (ipAddress != null && !ipAddress.isEmpty() && !"unknown".equalsIgnoreCase(ipAddress)) {
                // Handle multiple IPs (take the first one)
                if (ipAddress.contains(",")) {
                    ipAddress = ipAddress.split(",")[0].trim();
                }
                return ipAddress;
            }
        }
        return request.getRemoteAddr();
    }

    /**
     * Get user agent from HTTP request.
     */
    public static String getUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "Unknown";
    }

    /**
     * Check if request is from mobile device.
     */
    public static boolean isMobileDevice(HttpServletRequest request) {
        String userAgent = getUserAgent(request).toLowerCase();
        return userAgent.contains("mobile")
                || userAgent.contains("android")
                || userAgent.contains("iphone")
                || userAgent.contains("ipad");
    }

    /**
     * Get request origin.
     */
    public static String getRequestOrigin(HttpServletRequest request) {
        String origin = request.getHeader("Origin");
        if (origin == null || origin.isEmpty()) {
            origin = request.getHeader("Referer");
        }
        return origin != null ? origin : "Unknown";
    }
}