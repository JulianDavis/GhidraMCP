package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.core.service.Service;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.HashMap;
import java.util.Map;

/**
 * A service that provides number conversion between different representations (decimal, hexadecimal, bytes, ASCII, binary)
 * to prevent hallucinations related to numerical representations.
 * <p>
 * This service is designed to be used by AI assistants to ensure accurate numerical conversions.
 */
public class NumberConversionService implements Service {

    public static final String SERVICE_NAME = "NumberConversionService";
    private Program currentProgram;

    /**
     * Creates a new NumberConversionService.
     */
    public NumberConversionService() {
    }

    @Override
    public String getName() {
        return SERVICE_NAME;
    }

    @Override
    public void initialize(Program program) {
        this.currentProgram = program;
        Msg.info(this, "NumberConversionService initialized with program: " +
                (program != null ? program.getName() : "null"));
    }

    @Override
    public void dispose() {
        this.currentProgram = null;
        Msg.info(this, "NumberConversionService disposed");
    }

    /**
     * Creates a standardized error result.
     *
     * @param errorMessage the error message
     * @param errorCode optional error code
     * @return a standardized error result
     */
    private Map<String, Object> createErrorResult(String errorMessage, int errorCode) {
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> errorDetails = new HashMap<>();

        // Standard top-level structure
        response.put("status", "error");

        // Error details
        errorDetails.put("message", errorMessage);
        errorDetails.put("code", errorCode);

        response.put("error", errorDetails);

        return response;
    }

    /**
     * Creates a standardized error result with default error code (400).
     *
     * @param errorMessage the error message
     * @return a standardized error result
     */
    private Map<String, Object> createErrorResult(String errorMessage) {
        return createErrorResult(errorMessage, 400);
    }

    /**
     * Creates a standardized success result.
     *
     * @param data the data to include in the response
     * @return a standardized success result
     */
    private Map<String, Object> createSuccessResult(Map<String, Object> data) {
        Map<String, Object> response = new HashMap<>();

        // Standard top-level structure
        response.put("status", "success");
        response.put("data", data);

        return response;
    }

    /**
     * Convert a number (decimal, hexadecimal) to different representations.
     *
     * @param text Textual representation of the number to convert
     * @param size Size of the variable in bytes (optional, will be estimated if not provided)
     * @return A map containing the converted representations
     */
    public Map<String, Object> convertNumber(String text, Integer size) {
        try {
            // Parse the input number (supports decimal, hex, octal, etc.)
            long value;
            try {
                value = Long.parseLong(text.replace("0x", ""), 16);
            } catch (NumberFormatException e) {
                try {
                    value = Long.parseLong(text);
                } catch (NumberFormatException e2) {
                    try {
                        // Attempt to interpret as decimal
                        value = Long.decode(text);
                    } catch (NumberFormatException e3) {
                        return createErrorResult("Invalid number: " + text);
                    }
                }
            }

            // Estimate the size of the number if not provided
            if (size == null || size <= 0) {
                size = 0;
                long n = Math.abs(value);
                while (n != 0) {
                    size++;
                    n >>= 8; // Using 8 bits (1 byte) per step
                }
                if (size == 0) {
                    size = 1; // Minimum 1 byte for even zero
                }
            }

            // Convert the number to bytes
            byte[] bytes;
            try {
                bytes = new byte[size];
                for (int i = 0; i < size; i++) {
                    bytes[i] = (byte) ((value >> (i * 8)) & 0xFF);
                }
            } catch (Exception e) {
                return createErrorResult("Number " + text + " is too big for " + size + " bytes");
            }

            // Convert the bytes to ASCII
            String ascii = null;
            boolean isAscii = true;
            StringBuilder asciiBuilder = new StringBuilder();
            
            for (byte b : bytes) {
                if (b >= 32 && b <= 126) {
                    asciiBuilder.append((char) b);
                } else if (b != 0) { // Allow null bytes, but they stop the string
                    isAscii = false;
                    break;
                } else {
                    break; // Stop at null byte
                }
            }
            
            if (isAscii && asciiBuilder.length() > 0) {
                ascii = asciiBuilder.toString();
            }

            // Convert bytes to hex string
            StringBuilder bytesHex = new StringBuilder();
            for (byte b : bytes) {
                if (bytesHex.length() > 0) {
                    bytesHex.append(" ");
                }
                bytesHex.append(String.format("%02x", b));
            }

            // Create the data map
            Map<String, Object> data = new HashMap<>();
            data.put("decimal", Long.toString(value));
            data.put("hexadecimal", "0x" + Long.toHexString(value));
            data.put("bytes", bytesHex.toString());
            data.put("ascii", ascii); // Can be null
            data.put("binary", "0b" + Long.toBinaryString(value));

            return createSuccessResult(data);
        } catch (Exception e) {
            return createErrorResult("Failed to convert number: " + e.getMessage());
        }
    }
}