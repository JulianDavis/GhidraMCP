package com.juliandavis.ghidramcp.api.util;

import java.util.HashMap;
import java.util.Map;

/**
 * Utility class for creating standardized JSON responses.
 */
public final class ResponseUtil {

    // Private constructor to prevent instantiation
    private ResponseUtil() {}

    /**
     * Creates a standardized success response map.
     *
     * @param data The data payload for the success response.
     * @return A map representing the standardized success response.
     */
    public static Map<String, Object> createSuccessResponse(Map<String, Object> data) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("data", data != null ? data : new HashMap<>()); // Ensure data is never null
        return response;
    }

    /**
     * Creates a standardized error response map with a specific error code.
     *
     * @param errorMessage The error message.
     * @param errorCode    The HTTP-like error code (e.g., 400, 404, 500).
     * @return A map representing the standardized error response.
     */
    public static Map<String, Object> createErrorResponse(String errorMessage, int errorCode) {
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> errorDetails = new HashMap<>();

        response.put("status", "error");

        errorDetails.put("message", errorMessage != null ? errorMessage : "Unknown error"); // Ensure message is not null
        errorDetails.put("code", errorCode);

        response.put("error", errorDetails);

        return response;
    }

    /**
     * Creates a standardized error response map with a default error code (400 Bad Request).
     *
     * @param errorMessage The error message.
     * @return A map representing the standardized error response.
     */
    public static Map<String, Object> createErrorResponse(String errorMessage) {
        return createErrorResponse(errorMessage, 400); // Default to 400 Bad Request
    }

     /**
     * Creates a standardized error response map including additional context data.
     *
     * @param errorMessage The error message.
     * @param errorCode    The HTTP-like error code.
     * @param errorData    Additional context data to include in the error object.
     * @return A map representing the standardized error response.
     */
    public static Map<String, Object> createErrorResponse(String errorMessage, int errorCode, Map<String, Object> errorData) {
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> errorDetails = new HashMap<>();

        response.put("status", "error");

        errorDetails.put("message", errorMessage != null ? errorMessage : "Unknown error");
        errorDetails.put("code", errorCode);

        // Add additional context data if provided
        if (errorData != null) {
            errorDetails.putAll(errorData);
        }

        response.put("error", errorDetails);

        return response;
    }
}
