package com.juliandavis.ghidramcp.services.emulator.operations;

import com.juliandavis.ArchitectureHelper;
import com.juliandavis.ghidramcp.services.emulator.session.EmulatorSession;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Utility class for tracking stack changes during emulation.
 */
public class StackTracker {

    /**
     * Tracks stack changes for the current instruction
     * 
     * @param session The emulator session
     * @param instructionAddress The address of the current instruction
     */
    public static void trackStackChanges(EmulatorSession session, Address instructionAddress) {
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Get architecture-specific information
            ArchitectureHelper archHelper = new ArchitectureHelper(program, emulator);
            
            // Get stack growth direction - critical for correct stack analysis
            int stackGrowthDirection = archHelper.getStackGrowthDirection();
            
            // Get stack pointer value using architecture helper
            String spRegName = archHelper.getStackPointerRegisterName();
            if (spRegName == null) {
                Msg.warn(StackTracker.class, "Could not determine stack pointer register");
                return;
            }
            
            BigInteger spValue = archHelper.getStackPointerValue();
            if (spValue == null) {
                return;
            }
            
            // Create stack frame
            Map<String, Object> frame = new HashMap<>();
            frame.put("instruction", instructionAddress.toString());
            frame.put("stackPointer", spValue.toString(16));
            frame.put("register", spRegName);
            frame.put("stackGrowthDirection", stackGrowthDirection);
            frame.put("stackGrowthDirectionDesc", stackGrowthDirection > 0 ? "upward" : "downward");
            
            // Try to read some values from the stack
            Address stackAddr = program.getAddressFactory().getAddress(spValue.toString(16));
            List<Map<String, Object>> stackValues = new ArrayList<>();
            
            // Get pointer size for this architecture
            int pointerSize = archHelper.getPointerSize();
            
            // Read up to 8 stack values, accounting for stack growth direction
            for (int i = 0; i < 8; i++) {
                try {
                    // Address calculation based on stack growth direction
                    // For a downward-growing stack (typical), we look at higher addresses for stack values
                    // For an upward-growing stack, we look at lower addresses for stack values
                    Address valueAddr = stackAddr.add((long) i * pointerSize * stackGrowthDirection);
                    
                    byte[] bytes = new byte[pointerSize];
                    for (int j = 0; j < bytes.length; j++) {
                        bytes[j] = emulator.readMemoryByte(valueAddr.add(j));
                    }
                    
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("offset", i * pointerSize);
                    
                    // Convert to hex string
                    StringBuilder hexValue = new StringBuilder();
                    for (byte b : bytes) {
                        hexValue.append(String.format("%02x", b));
                    }
                    entry.put("value", "0x" + hexValue);
                    
                    // Include the address of this stack value
                    entry.put("address", valueAddr.toString());
                    
                    stackValues.add(entry);
                } catch (Exception e) {
                    // Stop if we can't read more
                    break;
                }
            }
            
            frame.put("values", stackValues);
            
            // Add to stack trace
            session.addStackFrame(frame);
        } catch (Exception e) {
            Msg.error(StackTracker.class, "Error tracking stack changes", e);
        }
    }
}