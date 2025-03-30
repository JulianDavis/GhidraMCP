package com.juliandavis;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;

import java.util.List;
import java.util.Map;

/**
 * Test script for validating the memory pattern search implementation.
 */
public class PatternSearchTest extends GhidraScript {

    @Override
    protected void run() throws Exception {
        println("Memory Pattern Search Test");
        println("=========================");
        
        Program program = currentProgram;
        if (program == null) {
            println("No program loaded!");
            return;
        }
        
        // Print basic program info
        Memory memory = program.getMemory();
        println("Program: " + program.getName());
        println("Memory blocks:");
        for (MemoryBlock block : memory.getBlocks()) {
            println(String.format("  %s: %s - %s (%s%s%s)", 
                block.getName(), 
                block.getStart(), 
                block.getEnd(),
                block.isRead() ? "r" : "-",
                block.isWrite() ? "w" : "-",
                block.isExecute() ? "x" : "-"));
        }
        println("");
        
        // Test cases
        TestCase[] testCases = {
            new TestCase("Standard hex pattern", "4883EC20", false, true, true, 20),
            new TestCase("Pattern with wildcards", "48??EC20", false, true, true, 20),
            new TestCase("ASCII case sensitive", "48656C6C6F", false, true, true, 20), // "Hello"
            new TestCase("ASCII case insensitive", "48656C6C6F", false, true, false, 20), // "Hello"
            new TestCase("Executable memory only", "4883EC20", true, false, true, 20),
            new TestCase("With spaces in pattern", "48 83 EC 20", false, true, true, 20),
        };
        
        for (TestCase test : testCases) {
            println("Test case: " + test.name);
            println("  Pattern: " + test.pattern);
            println("  Options: " + 
                    (test.searchExecutable ? "executable " : "") + 
                    (test.searchOnlyReadable ? "readable " : "") +
                    (test.caseSensitive ? "case-sensitive" : "case-insensitive"));
            
            long startTime = System.currentTimeMillis();
            List<Map<String, Object>> results = MemoryPatternSearchService.searchForPattern(
                    program, 
                    test.pattern, 
                    test.searchExecutable, 
                    test.searchOnlyReadable,
                    test.caseSensitive,
                    test.maxResults,
                    getMonitor());
            long endTime = System.currentTimeMillis();
            
            println(String.format("  Results: %d matches found in %d ms", 
                    results.size(), endTime - startTime));
            
            // Print first few results
            int numToPrint = Math.min(5, results.size());
            if (numToPrint > 0) {
                println("  Sample results:");
                for (int i = 0; i < numToPrint; i++) {
                    Map<String, Object> result = results.get(i);
                    String address = (String)result.get("address");
                    String context = (String)result.get("context");
                    println(String.format("    %s: %s", address, 
                            context != null && !context.isEmpty() ? context : "No context"));
                }
            }
            
            println("");
        }
        
        // Special test for comparison with old code if needed
        if (getScriptArgs().length > 0 && getScriptArgs()[0].equals("compare")) {
            println("Comparing with old implementation - Using the first test case");
            compareImplementations(program, testCases[0]);
        }
    }
    
    /**
     * Compare old and new implementations (only used if old implementation is still available)
     */
    private void compareImplementations(Program program, TestCase test) {
        // This is just a placeholder and would need to be updated if comparing with any old code
        println("Comparison with old implementation is not available in this version.");
    }
    
    /**
     * Class to hold test case information
     */
    private static class TestCase {
        public final String name;
        public final String pattern;
        public final boolean searchExecutable;
        public final boolean searchOnlyReadable;
        public final boolean caseSensitive;
        public final int maxResults;
        
        public TestCase(String name, String pattern, boolean searchExecutable, 
                boolean searchOnlyReadable, boolean caseSensitive, int maxResults) {
            this.name = name;
            this.pattern = pattern;
            this.searchExecutable = searchExecutable;
            this.searchOnlyReadable = searchOnlyReadable;
            this.caseSensitive = caseSensitive;
            this.maxResults = maxResults;
        }
    }
}
