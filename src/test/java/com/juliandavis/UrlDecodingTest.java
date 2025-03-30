package com.juliandavis;

import org.junit.Test;
import static org.junit.Assert.*;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Test class to verify URL decoding works correctly for comments
 */
public class UrlDecodingTest {

    @Test
    public void testUrlDecoding() {
        // The encoded comment example from the issue
        String encodedComment = "Multi-stage+decryption+routine%3A%0A-+Uses+bit-level+manipulation%0A-+Dynamic+function+calls+via+R11%0A-+Complex+control+flow+with+conditional+jumps%0A-+Likely+performs+in-memory+decryption+of+payload%2Fflag";
        
        // The expected decoded comment
        String expectedDecoded = "Multi-stage decryption routine:\n- Uses bit-level manipulation\n- Dynamic function calls via R11\n- Complex control flow with conditional jumps\n- Likely performs in-memory decryption of payload/flag";
        
        // Use the same decoder that our implementation uses
        String actualDecoded = URLDecoder.decode(encodedComment, StandardCharsets.UTF_8);
        
        // Verify they match
        assertEquals("The decoded comment should match the expected format", expectedDecoded, actualDecoded);
        
        // Print both for visual comparison
        System.out.println("Expected:");
        System.out.println(expectedDecoded);
        System.out.println("\nActual:");
        System.out.println(actualDecoded);
    }
}
