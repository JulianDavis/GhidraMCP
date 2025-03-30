package com.juliandavis;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.math.BigInteger;

/**
 * Helper class to abstract architecture-specific operations in the emulator.
 * Centralizes processor-specific logic for easier maintenance and extension.
 */
public class ArchitectureHelper {
    
    // Processor constants
    public static final String PROCESSOR_X86 = "x86";
    public static final String PROCESSOR_ARM = "ARM";
    public static final String PROCESSOR_MIPS = "MIPS";
    public static final String PROCESSOR_PPC = "PowerPC";
    
    private final Program program;
    private final EmulatorHelper emulator;
    private final String processorName;
    
    /**
     * Creates a new architecture helper for the specified program and emulator.
     * 
     * @param program The program being analyzed
     * @param emulator The emulator helper instance
     */
    public ArchitectureHelper(Program program, EmulatorHelper emulator) {
        this.program = program;
        this.emulator = emulator;
        this.processorName = program.getLanguage().getProcessor().toString();
        
        Msg.debug(this, "Created ArchitectureHelper for processor: " + processorName);
    }
    
    /**
     * Gets the name of the stack pointer register for the current architecture.
     * 
     * @return The name of the stack pointer register
     */
    public String getStackPointerRegisterName() {
        // First try to get it from EmulatorHelper
        Register spRegister = emulator.getStackPointerRegister();
        if (spRegister != null) {
            return spRegister.getName();
        }
        
        // Use architecture-specific fallbacks
        switch (processorName) {
            case PROCESSOR_X86:
                // x86 has different names depending on 32 or 64 bit
                if (program.getLanguage().getLanguageDescription().getSize() == 64) {
                    return "RSP";
                } else {
                    return "ESP";
                }
            case PROCESSOR_ARM:
                return "SP";
            case PROCESSOR_MIPS:
                return "sp";
            case PROCESSOR_PPC:
                return "r1"; // PowerPC uses r1 as stack pointer
            default:
                // Try common names
                for (String regName : new String[] {"SP", "ESP", "RSP", "sp"}) {
                    try {
                        emulator.readRegister(regName);
                        return regName;
                    } catch (Exception ignored) {
                        // Not this one
                    }
                }
                
                Msg.warn(this, "Could not determine stack pointer register for " + processorName);
                return null;
        }
    }
    
    /**
     * Gets the name of the program counter register for the current architecture.
     * 
     * @return The name of the program counter register
     */
    public String getProgramCounterRegisterName() {
        // First try to get it from EmulatorHelper
        Register pcRegister = emulator.getPCRegister();
        if (pcRegister != null) {
            return pcRegister.getName();
        }
        
        // Use architecture-specific fallbacks
        switch (processorName) {
            case PROCESSOR_X86:
                // x86 has different names depending on 32 or 64 bit
                if (program.getLanguage().getLanguageDescription().getSize() == 64) {
                    return "RIP";
                } else {
                    return "EIP";
                }
            case PROCESSOR_ARM:
                return "PC";
            case PROCESSOR_MIPS:
                return "pc";
            case PROCESSOR_PPC:
                return "IAR"; // PowerPC instruction address register
            default:
                // Try common names
                for (String regName : new String[] {"PC", "EIP", "RIP", "pc", "IAR"}) {
                    try {
                        emulator.readRegister(regName);
                        return regName;
                    } catch (Exception ignored) {
                        // Not this one
                    }
                }
                
                Msg.warn(this, "Could not determine program counter register for " + processorName);
                return null;
        }
    }
    
    /**
     * Gets the size of a pointer for the current architecture (in bytes).
     * 
     * @return The pointer size in bytes
     */
    public int getPointerSize() {
        return program.getLanguage().getLanguageDescription().getSize() / 8;
    }
    
    /**
     * Gets the stack growth direction (negative or positive).
     * Most architectures grow downward (negative), but some grow upward.
     * 
     * @return -1 for downward growth, 1 for upward growth
     */
    public int getStackGrowthDirection() {
        // Most architectures grow downward
        // Known upward-growing stack architectures
        if (processorName.equals("MicroBlaze")) {
            return 1;
            // All others grow downward
        }
        return -1;
    }
    
    /**
     * Gets the current stack pointer value as a BigInteger.
     * 
     * @return The stack pointer value, or null if not available
     */
    public BigInteger getStackPointerValue() {
        String spRegName = getStackPointerRegisterName();
        if (spRegName == null) {
            return null;
        }
        
        try {
            return emulator.readRegister(spRegName);
        } catch (Exception e) {
            Msg.warn(this, "Could not read stack pointer value: " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Gets the processor name.
     * 
     * @return The processor name
     */
    public String getProcessorName() {
        return processorName;
    }
    
    /**
     * Checks if the architecture is big endian.
     * 
     * @return true if big endian, false if little endian
     */
    public boolean isBigEndian() {
        return program.getLanguage().isBigEndian();
    }
}