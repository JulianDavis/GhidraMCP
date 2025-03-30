package com.juliandavis;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.emulate.Emulate;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.Msg;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Helper class for emulating standard I/O operations during emulation.
 * Intercepts calls to functions like printf, puts, write, read, etc. and
 * redirects them to the appropriate buffer in the EmulatorSession.
 */
public class StdioEmulationHelper extends ghidra.pcode.emulate.BreakCallBack {
    
    // Standard file descriptors
    private static final int STDIN_FD = 0;
    private static final int STDOUT_FD = 1;
    private static final int STDERR_FD = 2;
    
    // Known output function names (case-insensitive)
    private static final Set<String> STDOUT_FUNCTIONS = new HashSet<>(Arrays.asList(
            "printf", "puts", "fputs", "putchar", "putc", "fwrite", "write"
    ));
    
    // Known error output function names (case-insensitive)
    private static final Set<String> STDERR_FUNCTIONS = new HashSet<>(Arrays.asList(
            "fprintf", "perror", "vfprintf"
    ));
    
    // Known input function names (case-insensitive)
    private static final Set<String> STDIN_FUNCTIONS = new HashSet<>(Arrays.asList(
            "scanf", "gets", "fgets", "getchar", "getc", "fread", "read"
    ));
    
    private final EmulatorService.EmulatorSession session;
    private final EmulatorHelper emulator;
    private final Program program;
    private final ArchitectureHelper archHelper;
    private Emulate emulate;
    
    /**
     * Creates a new instance for handling standard I/O during emulation.
     * 
     * @param session The emulator session
     */
    public StdioEmulationHelper(EmulatorService.EmulatorSession session) {
        this.session = session;
        this.emulator = session.getEmulator();
        this.program = session.getProgram();
        this.archHelper = new ArchitectureHelper(program, emulator);
    }
    
    /**
     * Registers this helper with the emulator.
     */
    public void register() {
        emulator.registerDefaultCallOtherCallback(this);
    }
    
    @Override
    public void setEmulate(Emulate emu) {
        this.emulate = emu;
    }
    
    @Override
    public boolean addressCallback(Address addr) {
        // This method is called for all addresses reached during emulation
        // We're interested in function calls to stdio functions and system calls
        
        try {
            // First check if this is a system call instruction
            if (archHelper.isInstructionSystemCall(addr)) {
                return handleSyscall(null); // Pass null since we don't have the PcodeOp
            }
            
            // Get the function at this address
            Function function = program.getFunctionManager().getFunctionAt(addr);
            
            if (function != null) {
                String funcName = function.getName().toLowerCase();
                
                // Check if this is a known I/O function
                if (STDOUT_FUNCTIONS.contains(funcName)) {
                    return handleStdoutFunction(function, funcName);
                } else if (STDERR_FUNCTIONS.contains(funcName)) {
                    return handleStderrFunction(function, funcName);
                } else if (STDIN_FUNCTIONS.contains(funcName)) {
                    return handleStdinFunction(function, funcName);
                }
            }
            
            // Check for external symbols (imports) that might be I/O related
            Symbol symbol = program.getSymbolTable().getPrimarySymbol(addr);
            if (symbol != null && symbol.isExternal()) {
                String symName = symbol.getName().toLowerCase();
                
                if (STDOUT_FUNCTIONS.contains(symName)) {
                    return handleStdoutFunction(null, symName);
                } else if (STDERR_FUNCTIONS.contains(symName)) {
                    return handleStderrFunction(null, symName);
                } else if (STDIN_FUNCTIONS.contains(symName)) {
                    return handleStdinFunction(null, symName);
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error in addressCallback: " + e.getMessage());
        }
        
        // Not handled, continue normal execution
        return false;
    }
    
    public boolean pcodeCallback(PcodeOp op) {
        // This method is called for all p-code operations during emulation
        // We're interested in operations that represent system calls
        
        try {
            // Use the architecture helper to determine if this is a system call
            if (archHelper.isSystemCall(op)) {
                return handleSyscall(op);
            }
        } catch (Exception e) {
            Msg.warn(this, "Error in pcodeCallback: " + e.getMessage());
        }
        
        // Not handled, continue normal execution
        return false;
    }
    
    /**
     * Helper method to set a return value in the appropriate register
     * based on the processor architecture.
     * 
     * @param value The value to set
     */
    private void setReturnValue(long value) {
        try {
            String processor = program.getLanguage().getProcessor().toString();
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // x86 return value is in EAX
                emulator.writeRegister("EAX", BigInteger.valueOf(value));
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // ARM return value is in R0
                emulator.writeRegister("r0", BigInteger.valueOf(value));
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_MIPS)) {
                // MIPS return value is in V0
                emulator.writeRegister("v0", BigInteger.valueOf(value));
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_PPC)) {
                // PowerPC return value is in R3
                emulator.writeRegister("r3", BigInteger.valueOf(value));
            }
        } catch (Exception e) {
            Msg.warn(this, "Error setting return value: " + e.getMessage());
        }
    }
    
    /**
     * Handles standard output functions like printf, puts, etc.
     * 
     * @param function The function being called (may be null for external symbols)
     * @param funcName The name of the function
     * @return true if handled, false otherwise
     */
    private boolean handleStdoutFunction(Function function, String funcName) {
        try {
            // Delegate to specific handlers based on function name
            if ("printf".equals(funcName)) {
                handlePrintf(false);
                return true;
            } else if ("puts".equals(funcName)) {
                handlePuts();
                return true;
            } else if ("write".equals(funcName)) {
                handleWrite();
                return true;
            } else if ("putchar".equals(funcName) || "putc".equals(funcName)) {
                handlePutChar();
                return true;
            }
            
            // For other functions, just log that we encountered them
            Msg.info(this, "Unhandled stdout function: " + funcName);
        } catch (Exception e) {
            Msg.warn(this, "Error handling stdout function " + funcName + ": " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Handles standard error functions like fprintf, perror, etc.
     * 
     * @param function The function being called (may be null for external symbols)
     * @param funcName The name of the function
     * @return true if handled, false otherwise
     */
    private boolean handleStderrFunction(Function function, String funcName) {
        try {
            if ("fprintf".equals(funcName)) {
                handleFprintf();
                return true;
            } else if ("perror".equals(funcName)) {
                handlePerror();
                return true;
            }
            
            // For other functions, just log that we encountered them
            Msg.info(this, "Unhandled stderr function: " + funcName);
        } catch (Exception e) {
            Msg.warn(this, "Error handling stderr function " + funcName + ": " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Handles standard input functions like scanf, gets, etc.
     * 
     * @param function The function being called (may be null for external symbols)
     * @param funcName The name of the function
     * @return true if handled, false otherwise
     */
    private boolean handleStdinFunction(Function function, String funcName) {
        try {
            if ("scanf".equals(funcName)) {
                handleScanf();
                return true;
            } else if ("gets".equals(funcName) || "fgets".equals(funcName)) {
                handleGets();
                return true;
            } else if ("getchar".equals(funcName) || "getc".equals(funcName)) {
                handleGetChar();
                return true;
            } else if ("read".equals(funcName)) {
                handleRead();
                return true;
            }
            
            // For other functions, just log that we encountered them
            Msg.info(this, "Unhandled stdin function: " + funcName);
        } catch (Exception e) {
            Msg.warn(this, "Error handling stdin function " + funcName + ": " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Handles system calls related to I/O.
     * 
     * @param op The p-code operation representing the system call
     * @return true if handled, false otherwise
     */
    private boolean handleSyscall(PcodeOp op) {
        try {
            // Get the syscall number using the architecture helper
            int syscallNum = archHelper.getSyscallNumber();
            String processor = archHelper.getProcessorName();
            
            if (syscallNum != -1) {
                // Handle based on syscall number - these vary by OS
                if (processor.equals(ArchitectureHelper.PROCESSOR_X86) || 
                    processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                    
                    if (syscallNum == 4) { // write
                        return handleSyscallWrite();
                    } else if (syscallNum == 3) { // read
                        return handleSyscallRead();
                    }
                } else if (processor.equals(ArchitectureHelper.PROCESSOR_MIPS)) {
                    if (syscallNum == 4004) { // write
                        return handleSyscallWrite();
                    } else if (syscallNum == 4003) { // read
                        return handleSyscallRead();
                    }
                } else if (processor.equals(ArchitectureHelper.PROCESSOR_PPC)) {
                    // PowerPC syscall numbers (if needed)
                    // Add PowerPC-specific syscall handling here
                }
                
                Msg.info(this, "Unhandled syscall number: " + syscallNum + " for processor: " + processor);
            } else {
                Msg.warn(this, "Could not determine syscall number for processor: " + processor);
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling syscall: " + e.getMessage());
        }
        
        return false;
    }
    
    // Placeholder methods for specific handlers
    private void handlePrintf(boolean isStderr) {
        try {
            // Get the format string parameter
            String processor = program.getLanguage().getProcessor().toString();
            
            // Get pointer to format string
            BigInteger formatPtr = null;
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86 32-bit, first parameter is typically at ESP+4
                BigInteger esp = emulator.readRegister("ESP");
                Address paramAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(4)).toString(16));
                byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    bytes[i] = emulator.readMemoryByte(paramAddr.add(i));
                }
                formatPtr = new BigInteger(bytesToHex(bytes), 16);
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM, first parameter is typically in R0
                formatPtr = emulator.readRegister("r0");
            } else {
                // For other architectures, we'd need to implement parameter retrieval
                Msg.warn(this, "Printf parameter retrieval not implemented for " + processor);
                return;
            }
            
            // Now read the format string from memory
            if (formatPtr != null) {
                // Create address from the pointer
                Address strAddr = program.getAddressFactory().getAddress(formatPtr.toString(16));
                
                // Read until null terminator
                StringBuilder str = new StringBuilder();
                byte b;
                int maxLength = 1024; // Avoid infinite loops with a reasonable maximum
                
                for (int i = 0; i < maxLength; i++) {
                    b = emulator.readMemoryByte(strAddr.add(i));
                    if (b == 0) {
                        break;
                    }
                    str.append((char)b);
                }
                
                // Output to the appropriate buffer
                String output = str.toString();
                
                // In a real implementation, we'd also handle format specifiers
                // by reading additional parameters, but for simplicity we'll
                // just output the raw string
                
                if (isStderr) {
                    session.appendStderr(output);
                } else {
                    session.appendStdout(output);
                }
                
                // Return a success value in the appropriate register
                // (typically the length of the string)
                setReturnValue(output.length());
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling printf: " + e.getMessage());
        }
    }
    
    private void handlePuts() {
        try {
            // Similar to printf, but simpler (just one string parameter)
            String processor = program.getLanguage().getProcessor().toString();
            
            // Get pointer to the string
            BigInteger strPtr = null;
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86 32-bit, parameter is at ESP+4
                BigInteger esp = emulator.readRegister("ESP");
                Address paramAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(4)).toString(16));
                byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    bytes[i] = emulator.readMemoryByte(paramAddr.add(i));
                }
                strPtr = new BigInteger(bytesToHex(bytes), 16);
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM, parameter is in R0
                strPtr = emulator.readRegister("r0");
            } else {
                Msg.warn(this, "Puts parameter retrieval not implemented for " + processor);
                return;
            }
            
            // Read the string from memory
            if (strPtr != null) {
                Address strAddr = program.getAddressFactory().getAddress(strPtr.toString(16));
                
                StringBuilder str = new StringBuilder();
                byte b;
                int maxLength = 1024;
                
                for (int i = 0; i < maxLength; i++) {
                    b = emulator.readMemoryByte(strAddr.add(i));
                    if (b == 0) {
                        break;
                    }
                    str.append((char)b);
                }
                
                // Output the string with a newline
                String output = str + "\n";
                session.appendStdout(output);
                
                // Return success (puts returns a non-negative value on success)
                setReturnValue(1);
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling puts: " + e.getMessage());
        }
    }
    private boolean handleWrite() {
        // Similar to syscall write but with C function calling convention
        try {
            BigInteger fdBigInt = null;
            BigInteger bufPtr = null;
            BigInteger count = null;
            
            String processor = program.getLanguage().getProcessor().toString();
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86 32-bit, parameters are on the stack
                BigInteger esp = emulator.readRegister("ESP");
                
                // First parameter (fd)
                Address fdAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(4)).toString(16));
                byte[] fdBytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    fdBytes[i] = emulator.readMemoryByte(fdAddr.add(i));
                }
                fdBigInt = new BigInteger(bytesToHex(fdBytes), 16);
                
                // Second parameter (buf)
                Address bufAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(8)).toString(16));
                byte[] bufBytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    bufBytes[i] = emulator.readMemoryByte(bufAddr.add(i));
                }
                bufPtr = new BigInteger(bytesToHex(bufBytes), 16);
                
                // Third parameter (count)
                Address countAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(12)).toString(16));
                byte[] countBytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    countBytes[i] = emulator.readMemoryByte(countAddr.add(i));
                }
                count = new BigInteger(bytesToHex(countBytes), 16);
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM, parameters are in R0, R1, R2
                fdBigInt = emulator.readRegister("r0");
                bufPtr = emulator.readRegister("r1");
                count = emulator.readRegister("r2");
            }
            
            if (fdBigInt != null && bufPtr != null && count != null) {
                int fd = fdBigInt.intValue();
                int countInt = count.intValue();
                
                // Only handle stdout (1) and stderr (2)
                if (fd == STDOUT_FD || fd == STDERR_FD) {
                    // Read the buffer
                    Address bufAddr = program.getAddressFactory().getAddress(bufPtr.toString(16));
                    
                    StringBuilder str = new StringBuilder();
                    for (int i = 0; i < countInt && i < 4096; i++) { // Limit to 4KB for safety
                        byte b = emulator.readMemoryByte(bufAddr.add(i));
                        str.append((char)b);
                    }
                    
                    // Output to the appropriate buffer
                    if (fd == STDOUT_FD) {
                        session.appendStdout(str.toString());
                    } else {
                        session.appendStderr(str.toString());
                    }
                    
                    // Return the number of bytes written
                    setReturnValue(countInt);
                    return true;
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling write function: " + e.getMessage());
        }
        
        return false;
    }
    private boolean handlePutChar() {
        try {
            // Get the character parameter
            int ch = -1;
            String processor = program.getLanguage().getProcessor().toString();
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86 32-bit, parameter is on the stack
                BigInteger esp = emulator.readRegister("ESP");
                Address paramAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(4)).toString(16));
                byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    bytes[i] = emulator.readMemoryByte(paramAddr.add(i));
                }
                ch = new BigInteger(bytesToHex(bytes), 16).intValue();
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM, parameter is in R0
                ch = emulator.readRegister("r0").intValue();
            }
            
            if (ch >= 0) {
                // Output the character
                session.appendStdout(String.valueOf((char)ch));
                
                // Return the character value
                setReturnValue(ch);
                return true;
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling putchar: " + e.getMessage());
        }
        
        return false;
    }
    private boolean handleFprintf() {
        try {
            // First check if the FILE* corresponds to stderr
            BigInteger filePtr = null;
            String processor = program.getLanguage().getProcessor().toString();
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86 32-bit, first parameter (FILE*) is at ESP+4
                BigInteger esp = emulator.readRegister("ESP");
                Address paramAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(4)).toString(16));
                byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    bytes[i] = emulator.readMemoryByte(paramAddr.add(i));
                }
                filePtr = new BigInteger(bytesToHex(bytes), 16);
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM, first parameter is in R0
                filePtr = emulator.readRegister("r0");
            }
            
            // This is a simplification - in real code we'd need to check if the FILE* is stderr
            // For our purposes, we'll assume it always is since we don't have good ways to check
            
            // Handle like printf but to stderr
            handlePrintf(true);
            return true;
        } catch (Exception e) {
            Msg.warn(this, "Error handling fprintf: " + e.getMessage());
        }
        
        return false;
    }
    private boolean handlePerror() {
        try {
            // Get the error message parameter
            BigInteger msgPtr = null;
            String processor = program.getLanguage().getProcessor().toString();
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86 32-bit, parameter is on the stack
                BigInteger esp = emulator.readRegister("ESP");
                Address paramAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(4)).toString(16));
                byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    bytes[i] = emulator.readMemoryByte(paramAddr.add(i));
                }
                msgPtr = new BigInteger(bytesToHex(bytes), 16);
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM, parameter is in R0
                msgPtr = emulator.readRegister("r0");
            }
            
            if (msgPtr != null) {
                // Read the message string
                Address msgAddr = program.getAddressFactory().getAddress(msgPtr.toString(16));
                StringBuilder msg = new StringBuilder();
                byte b;
                int maxLength = 1024;
                
                for (int i = 0; i < maxLength; i++) {
                    b = emulator.readMemoryByte(msgAddr.add(i));
                    if (b == 0) {
                        break;
                    }
                    msg.append((char)b);
                }
                
                // Output to stderr with "error" prefix
                String output = msg + ": Unknown error\n";
                session.appendStderr(output);
                
                return true;
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling perror: " + e.getMessage());
        }
        
        return false;
    }
    private boolean handleScanf() {
        try {
            // Get the format string parameter
            BigInteger formatPtr = null;
            String processor = program.getLanguage().getProcessor().toString();
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86 32-bit, first parameter is at ESP+4
                BigInteger esp = emulator.readRegister("ESP");
                Address paramAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(4)).toString(16));
                byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    bytes[i] = emulator.readMemoryByte(paramAddr.add(i));
                }
                formatPtr = new BigInteger(bytesToHex(bytes), 16);
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM, first parameter is in R0
                formatPtr = emulator.readRegister("r0");
            }
            
            if (formatPtr != null) {
                // Read the format string
                Address formatAddr = program.getAddressFactory().getAddress(formatPtr.toString(16));
                StringBuilder formatStr = new StringBuilder();
                byte b;
                int maxLength = 1024;
                
                for (int i = 0; i < maxLength; i++) {
                    b = emulator.readMemoryByte(formatAddr.add(i));
                    if (b == 0) {
                        break;
                    }
                    formatStr.append((char)b);
                }
                
                // For simplicity, we'll just read data from stdin buffer
                // and assume it matches what's expected by the format string
                String stdinData = session.readStdin(100); // Read reasonable amount
                
                if (!stdinData.isEmpty()) {
                    // In a real implementation, we'd parse the format string,
                    // extract the data based on the format specifiers, and write
                    // it to the output locations specified by the other parameters.
                    
                    // For now, just return the number of items successfully read
                    setReturnValue(1); // Assume we read one item successfully
                } else {
                    // No data available
                    setReturnValue(0);
                }
                
                return true;
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling scanf: " + e.getMessage());
        }
        
        return false;
    }
    private boolean handleGets() {
        try {
            // Get the buffer parameter
            BigInteger bufPtr = null;
            String processor = program.getLanguage().getProcessor().toString();
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86 32-bit, first parameter is at ESP+4
                BigInteger esp = emulator.readRegister("ESP");
                Address paramAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(4)).toString(16));
                byte[] bytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    bytes[i] = emulator.readMemoryByte(paramAddr.add(i));
                }
                bufPtr = new BigInteger(bytesToHex(bytes), 16);
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM, first parameter is in R0
                bufPtr = emulator.readRegister("r0");
            }
            
            if (bufPtr != null) {
                // Read data from stdin buffer until newline or EOF
                String input = session.readStdin(1024); // Read a reasonable amount
                
                if (input.isEmpty()) {
                    // No data available
                    setReturnValue(0); // Indicate failure
                    return true;
                }
                
                // Make sure it ends with a newline
                if (!input.endsWith("\n")) {
                    input += "\n";
                }
                
                // Write the data to the buffer
                Address bufAddr = program.getAddressFactory().getAddress(bufPtr.toString(16));
                for (int i = 0; i < input.length(); i++) {
                    emulator.writeMemory(bufAddr.add(i), new byte[] { (byte)input.charAt(i) });
                }
                
                // Add null terminator
                emulator.writeMemory(bufAddr.add(input.length()), new byte[] { (byte)0 });
                
                // Return the buffer pointer (gets returns a pointer to the buffer)
                setReturnValue(bufPtr.longValue());
                return true;
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling gets: " + e.getMessage());
        }
        
        return false;
    }
    private boolean handleGetChar() {
        try {
            // Read a single character from stdin
            String input = session.readStdin(1);
            
            if (input.isEmpty()) {
                // No data available, return EOF (-1)
                setReturnValue(-1);
            } else {
                // Return the character value
                setReturnValue((int)input.charAt(0));
            }
            
            return true;
        } catch (Exception e) {
            Msg.warn(this, "Error handling getchar: " + e.getMessage());
        }
        
        return false;
    }
    private boolean handleRead() {
        try {
            // Get parameters for read(fd, buf, count)
            BigInteger fdBigInt = null;
            BigInteger bufPtr = null;
            BigInteger count = null;
            
            String processor = program.getLanguage().getProcessor().toString();
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86 32-bit, parameters are on the stack
                BigInteger esp = emulator.readRegister("ESP");
                
                // First parameter (fd)
                Address fdAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(4)).toString(16));
                byte[] fdBytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    fdBytes[i] = emulator.readMemoryByte(fdAddr.add(i));
                }
                fdBigInt = new BigInteger(bytesToHex(fdBytes), 16);
                
                // Second parameter (buf)
                Address bufAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(8)).toString(16));
                byte[] bufBytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    bufBytes[i] = emulator.readMemoryByte(bufAddr.add(i));
                }
                bufPtr = new BigInteger(bytesToHex(bufBytes), 16);
                
                // Third parameter (count)
                Address countAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(12)).toString(16));
                byte[] countBytes = new byte[4];
                for (int i = 0; i < 4; i++) {
                    countBytes[i] = emulator.readMemoryByte(countAddr.add(i));
                }
                count = new BigInteger(bytesToHex(countBytes), 16);
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM, parameters are in R0, R1, R2
                fdBigInt = emulator.readRegister("r0");
                bufPtr = emulator.readRegister("r1");
                count = emulator.readRegister("r2");
            }
            
            if (fdBigInt != null && bufPtr != null && count != null) {
                int fd = fdBigInt.intValue();
                int countInt = count.intValue();
                
                // Only handle stdin (0)
                if (fd == STDIN_FD) {
                    // Read data from stdin buffer
                    String input = session.readStdin(countInt);
                    
                    if (input.isEmpty()) {
                        // No data available
                        setReturnValue(0);
                        return true;
                    }
                    
                    // Write the data to the buffer
                    Address bufAddr = program.getAddressFactory().getAddress(bufPtr.toString(16));
                    for (int i = 0; i < input.length(); i++) {
                        emulator.writeMemory(bufAddr.add(i), new byte[] { (byte)input.charAt(i) });
                    }
                    
                    // Return the number of bytes read
                    setReturnValue(input.length());
                    return true;
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling read function: " + e.getMessage());
        }
        
        return false;
    }
    private boolean handleSyscallWrite() {
        try {
            // Get parameters
            BigInteger fdBigInt = null;
            BigInteger bufPtr = null;
            BigInteger count = null;
            
            String processor = program.getLanguage().getProcessor().toString();
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86 Linux, fd is in EBX, buf in ECX, count in EDX
                fdBigInt = emulator.readRegister("EBX");
                bufPtr = emulator.readRegister("ECX");
                count = emulator.readRegister("EDX");
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM Linux, fd is in R0, buf in R1, count in R2
                fdBigInt = emulator.readRegister("r0");
                bufPtr = emulator.readRegister("r1");
                count = emulator.readRegister("r2");
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_MIPS)) {
                // For MIPS Linux, fd is in A0, buf in A1, count in A2
                fdBigInt = emulator.readRegister("a0");
                bufPtr = emulator.readRegister("a1");
                count = emulator.readRegister("a2");
            }
            
            if (fdBigInt != null && bufPtr != null && count != null) {
                int fd = fdBigInt.intValue();
                int countInt = count.intValue();
                
                // Only handle stdout (1) and stderr (2)
                if (fd == STDOUT_FD || fd == STDERR_FD) {
                    // Read the buffer
                    Address bufAddr = program.getAddressFactory().getAddress(bufPtr.toString(16));
                    
                    StringBuilder str = new StringBuilder();
                    for (int i = 0; i < countInt && i < 4096; i++) { // Limit to 4KB for safety
                        byte b = emulator.readMemoryByte(bufAddr.add(i));
                        str.append((char)b);
                    }
                    
                    // Output to the appropriate buffer
                    if (fd == STDOUT_FD) {
                        session.appendStdout(str.toString());
                    } else {
                        session.appendStderr(str.toString());
                    }
                    
                    // Return the number of bytes written
                    setReturnValue(countInt);
                    return true;
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling write syscall: " + e.getMessage());
        }
        
        return false;
    }
    private boolean handleSyscallRead() {
        try {
            // Get parameters
            BigInteger fdBigInt = null;
            BigInteger bufPtr = null;
            BigInteger count = null;
            
            String processor = program.getLanguage().getProcessor().toString();
            
            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86 Linux, fd is in EBX, buf in ECX, count in EDX
                fdBigInt = emulator.readRegister("EBX");
                bufPtr = emulator.readRegister("ECX");
                count = emulator.readRegister("EDX");
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM Linux, fd is in R0, buf in R1, count in R2
                fdBigInt = emulator.readRegister("r0");
                bufPtr = emulator.readRegister("r1");
                count = emulator.readRegister("r2");
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_MIPS)) {
                // For MIPS Linux, fd is in A0, buf in A1, count in A2
                fdBigInt = emulator.readRegister("a0");
                bufPtr = emulator.readRegister("a1");
                count = emulator.readRegister("a2");
            }
            
            if (fdBigInt != null && bufPtr != null && count != null) {
                int fd = fdBigInt.intValue();
                int countInt = count.intValue();
                
                // Only handle stdin (0)
                if (fd == STDIN_FD) {
                    // Read data from stdin buffer
                    String input = session.readStdin(countInt);
                    
                    if (input.isEmpty()) {
                        // No data available
                        setReturnValue(0);
                        return true;
                    }
                    
                    // Write the data to the buffer
                    Address bufAddr = program.getAddressFactory().getAddress(bufPtr.toString(16));
                    for (int i = 0; i < input.length(); i++) {
                        emulator.writeMemory(bufAddr.add(i), new byte[] { (byte)input.charAt(i) });
                    }
                    
                    // Return the number of bytes read
                    setReturnValue(input.length());
                    return true;
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling read syscall: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Convert a byte array to a hex string.
     * 
     * @param bytes The byte array to convert
     * @return The hex string representation
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}