package com.juliandavis.ghidramcp.emulation.arch;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
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
    
    /**
     * Determines if a PcodeOp represents a system call based on opcode and architecture.
     * 
     * @param op The PcodeOp to check
     * @return true if the PcodeOp is likely a system call, false otherwise
     */
    public boolean isSystemCall(PcodeOp op) {
        if (op == null) {
            return false;
        }
        
        try {
            // Check if this is a CALLOTHER operation which might represent a syscall
            if (op.getOpcode() == PcodeOp.CALLOTHER) {
                return isCallotherSystemCall(op);
            }
            
            // Get the address from the operation's sequence number
            Address addr = op.getSeqnum().getTarget();
            if (addr == null) {
                return false;
            }
            
            // Check the instruction at this address
            return isInstructionSystemCall(addr);
        } catch (Exception e) {
            Msg.warn(this, "Error checking for system call: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Determines if a CALLOTHER operation represents a system call.
     * 
     * @param op The CALLOTHER PcodeOp to check
     * @return true if the CALLOTHER represents a system call, false otherwise
     */
    private boolean isCallotherSystemCall(PcodeOp op) {
        try {
            // CALLOTHER operations use their first input to identify the specific operation
            if (op.getNumInputs() == 0) {
                return false;
            }
            
            // Get the special operation index
            int specialOpIndex = (int) op.getInput(0).getOffset();
            
            // Different architectures use different CALLOTHER indices for syscalls
            switch (processorName) {
                case PROCESSOR_X86:
                    // In some x86 P-code implementations, index 0 is used for syscalls
                    // This is architecture and compiler dependent
                    return specialOpIndex == 0;
                    
                case PROCESSOR_ARM:
                    // ARM might use a specific CALLOTHER index for SWI/SVC
                    return specialOpIndex == 0;
                    
                case PROCESSOR_MIPS:
                    // MIPS might use a specific CALLOTHER index for syscall
                    return specialOpIndex == 0;
                    
                default:
                    // Default conservative approach
                    return false;
            }
        } catch (Exception e) {
            Msg.warn(this, "Error checking CALLOTHER for system call: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Determines if an instruction at the given address is a system call.
     * Uses architecture-specific instruction patterns to identify syscall instructions.
     * 
     * @param addr The address to check
     * @return true if the instruction is a system call, false otherwise
     */
    public boolean isInstructionSystemCall(Address addr) {
        try {
            // Get the instruction at this address
            Instruction instr = program.getListing().getInstructionAt(addr);
            if (instr == null) {
                return false;
            }
            
            String mnemonic = instr.getMnemonicString().toLowerCase();
            
            // Check based on processor type
            switch (processorName) {
                case PROCESSOR_X86:
                    // x86 syscall instructions: int 0x80, syscall, sysenter
                    if (mnemonic.equals("int")) {
                        // Check for int 0x80 - common Linux syscall mechanism on 32-bit x86
                        Object[] operands = instr.getOpObjects(0);
                        if (operands.length > 0 && operands[0] instanceof Integer) {
                            Integer value = (Integer) operands[0];
                            return value == 0x80;
                        }
                    }
                    // Direct syscall instructions for 64-bit
                    return mnemonic.equals("syscall") || mnemonic.equals("sysenter");
                    
                case PROCESSOR_ARM:
                    // ARM syscall instructions: swi, svc
                    return mnemonic.equals("swi") || mnemonic.equals("svc");
                    
                case PROCESSOR_MIPS:
                    // MIPS syscall instruction: syscall
                    return mnemonic.equals("syscall");
                    
                case PROCESSOR_PPC:
                    // PowerPC syscall: sc
                    return mnemonic.equals("sc");
                    
                default:
                    // Unknown architecture, check for common syscall mnemonics
                    return mnemonic.equals("syscall") || mnemonic.equals("svc") || 
                           mnemonic.equals("swi") || mnemonic.equals("int") || 
                           mnemonic.equals("sc");
            }
        } catch (Exception e) {
            Msg.warn(this, "Error checking instruction for system call: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Gets the register name that holds the system call number for the current architecture.
     * 
     * @return The register name containing the syscall number
     */
    public String getSyscallNumberRegister() {
        switch (processorName) {
            case PROCESSOR_X86:
                // x86 uses EAX/RAX for syscall numbers
                if (program.getLanguage().getLanguageDescription().getSize() == 64) {
                    return "RAX";
                } else {
                    return "EAX";
                }
                
            case PROCESSOR_ARM:
                // ARM uses R7 for syscall numbers (thumb state uses R7 as well)
                return "r7";
                
            case PROCESSOR_MIPS:
                // MIPS uses V0 for syscall numbers
                return "v0";
                
            case PROCESSOR_PPC:
                // PowerPC typically uses R0 for syscall numbers
                return "r0";
                
            default:
                // Try common syscall registers
                for (String regName : new String[] {"EAX", "RAX", "r7", "v0", "r0"}) {
                    try {
                        emulator.readRegister(regName);
                        return regName;
                    } catch (Exception ignored) {
                        // Not this one
                    }
                }
                
                Msg.warn(this, "Could not determine syscall number register for " + processorName);
                return null;
        }
    }
    
    /**
     * Gets the current system call number from the appropriate register.
     * 
     * @return The syscall number or -1 if not available
     */
    public int getSyscallNumber() {
        String syscallReg = getSyscallNumberRegister();
        if (syscallReg == null) {
            return -1;
        }
        
        try {
            BigInteger value = emulator.readRegister(syscallReg);
            return value.intValue();
        } catch (Exception e) {
            Msg.warn(this, "Could not read syscall number from register: " + e.getMessage());
            return -1;
        }
    }
}