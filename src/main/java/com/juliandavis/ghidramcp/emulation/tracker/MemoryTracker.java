package com.juliandavis.ghidramcp.emulation.tracker;

import com.juliandavis.ghidramcp.core.util.MemoryUtil;
import com.juliandavis.ghidramcp.emulation.arch.ArchitectureHelper;
import com.juliandavis.ghidramcp.emulation.core.EmulatorSession;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;

/**
 * Utility class for tracking memory operations during emulation.
 * Provides methods for analyzing memory reads and writes.
 */
public class MemoryTracker {

    /**
     * Analyzes memory reads from an emulation session.
     * 
     * @param session The emulator session
     * @return A map containing information about memory reads
     */
    public static Map<String, Object> analyzeMemoryReads(EmulatorSession session) {
        if (session == null) {
            return Map.of("success", false, "error", "Invalid session");
        }
        
        try {
            // Get architecture-specific information
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            ArchitectureHelper archHelper = new ArchitectureHelper(program, emulator);
            boolean isBigEndian = archHelper.isBigEndian();
            
            // Group contiguous reads
            SortedMap<Address, byte[]> contiguousReads = MemoryUtil.groupContiguousWrites(session.getMemoryReads());
            
            // Create information for each read
            List<Map<String, Object>> readsInfo = new ArrayList<>();
            for (Map.Entry<Address, byte[]> entry : contiguousReads.entrySet()) {
                readsInfo.add(MemoryUtil.createMemoryWriteInfo(entry, isBigEndian));
            }
            
            // Create result map
            return Map.of(
                "success", true,
                "reads", readsInfo,
                "count", readsInfo.size(),
                "totalBytes", session.getMemoryReads().size()
            );
        } catch (Exception e) {
            Msg.error(MemoryTracker.class, "Error analyzing memory reads", e);
            return Map.of("success", false, "error", "Error analyzing memory reads: " + e.getMessage());
        }
    }
    
    /**
     * Analyzes memory writes from an emulation session.
     * 
     * @param session The emulator session
     * @return A map containing information about memory writes
     */
    public static Map<String, Object> analyzeMemoryWrites(EmulatorSession session) {
        if (session == null) {
            return Map.of("success", false, "error", "Invalid session");
        }
        
        try {
            // Get architecture-specific information
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            ArchitectureHelper archHelper = new ArchitectureHelper(program, emulator);
            boolean isBigEndian = archHelper.isBigEndian();
            
            // Group contiguous writes
            SortedMap<Address, byte[]> contiguousWrites = MemoryUtil.groupContiguousWrites(session.getMemoryWrites());
            
            // Create information for each write
            List<Map<String, Object>> writesInfo = new ArrayList<>();
            for (Map.Entry<Address, byte[]> entry : contiguousWrites.entrySet()) {
                writesInfo.add(MemoryUtil.createMemoryWriteInfo(entry, isBigEndian));
            }
            
            // Create result map
            return Map.of(
                "success", true,
                "writes", writesInfo,
                "count", writesInfo.size(),
                "totalBytes", session.getMemoryWrites().size()
            );
        } catch (Exception e) {
            Msg.error(MemoryTracker.class, "Error analyzing memory writes", e);
            return Map.of("success", false, "error", "Error analyzing memory writes: " + e.getMessage());
        }
    }
    
    /**
     * Checks if a memory address falls within a specific memory region.
     * 
     * @param session The emulator session
     * @param address The address to check
     * @param regionName The name of the region to check (e.g., "stack", "heap")
     * @return true if the address is in the specified region, false otherwise
     */
    public static boolean isAddressInRegion(EmulatorSession session, Address address, String regionName) {
        if (session == null || address == null || regionName == null) {
            return false;
        }
        
        try {
            // Get architecture-specific information
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            ArchitectureHelper archHelper = new ArchitectureHelper(program, emulator);
            
            // Check if address is in stack region
            if (regionName.equalsIgnoreCase("stack")) {
                // Get stack pointer
                String spRegName = archHelper.getStackPointerRegisterName();
                if (spRegName != null) {
                    Address sp = program.getAddressFactory().getAddress(
                            emulator.readRegister(spRegName).toString(16));
                    
                    // Estimate stack region (adjust as needed)
                    long stackSize = 0x10000; // 64KB stack size estimation
                    int direction = archHelper.getStackGrowthDirection();
                    Address stackBottom = direction < 0 ? sp : sp.subtract(stackSize);
                    Address stackTop = direction < 0 ? sp.add(stackSize) : sp;
                    
                    // Check if address is within stack region
                    return (address.compareTo(stackBottom) >= 0 && address.compareTo(stackTop) <= 0);
                }
            }
            
            // Add more region checks as needed (heap, etc.)
            
            return false;
        } catch (Exception e) {
            Msg.error(MemoryTracker.class, "Error checking address region", e);
            return false;
        }
    }
}
