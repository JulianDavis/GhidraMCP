package com.juliandavis;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
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
    private final String operatingSystem;
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
        // Determine OS and check if it's supported
        this.operatingSystem = SyscallMappings.determineOS(program);
        boolean osSupported = SyscallMappings.isOSSupported(this.operatingSystem);
        boolean archSupported = SyscallMappings.isSupported(this.operatingSystem, archHelper.getProcessorName());
        
        if (!osSupported) {
            Msg.warn(this, "Operating system " + this.operatingSystem + " has limited syscall support");
        }
        if (!archSupported) {
            Msg.warn(this, "Architecture " + archHelper.getProcessorName() + " on " + 
                    this.operatingSystem + " has limited syscall support");
        }
        
        Msg.debug(this, "StdioEmulationHelper initialized for OS: " + this.operatingSystem + 
                   ", processor: " + archHelper.getProcessorName());
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
                // Get syscall information if available
                int syscallNum = archHelper.getSyscallNumber();
                String os = SyscallMappings.determineOS(program);
                String processor = archHelper.getProcessorName();
                
                if (syscallNum != -1) {
                    // Get syscall information
                    SyscallMappings.SyscallInfo syscallInfo = SyscallMappings.getSyscallInfo(os, processor, syscallNum);
                    
                    if (syscallInfo != null) {
                        String syscallName = syscallInfo.getName();
                        int paramCount = SyscallMappings.getSyscallParamCount(os, processor, syscallNum);
                        
                        // Log enhanced syscall information
                        Msg.debug(this, "Detected syscall: " + syscallName + 
                                  " (" + syscallNum + ") for " + os + "/" + processor + 
                                  ", params: " + paramCount);
                        
                        // Check if this is an I/O-related syscall for special handling
                        if (SyscallMappings.isIOSyscall(os, processor, syscallNum)) {
                            Msg.debug(this, "I/O-related syscall detected: " + syscallName);
                        }
                    }
                }
                
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
     * Helper method to read a parameter from a function call based on architecture.
     * This centralizes the logic for extracting parameters across different processor architectures.
     * 
     * @param paramIndex The index of the parameter (0-based)
     * @return The parameter value as a BigInteger, or null if not retrievable
     */
    private BigInteger readFunctionParameter(int paramIndex) {
        try {
            String processor = archHelper.getProcessorName();
            int pointerSize = archHelper.getPointerSize();

            if (processor.equals(ArchitectureHelper.PROCESSOR_X86)) {
                // For x86, parameters are on the stack (ESP+4, ESP+8, etc.)
                BigInteger esp = emulator.readRegister("ESP");
                int offset = (paramIndex + 1) * pointerSize;  // +1 because first param is at ESP+4
                Address paramAddr = program.getAddressFactory().getAddress(esp.add(BigInteger.valueOf(offset)).toString(16));
                return readMemoryPointer(paramAddr, pointerSize);
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                // For ARM, first 4 parameters are in registers r0-r3, then on stack
                if (paramIndex < 4) {
                    return emulator.readRegister("r" + paramIndex);
                } else {
                    // For params after r3, they're on the stack
                    BigInteger sp = emulator.readRegister("SP");
                    int offset = (paramIndex - 4) * pointerSize;
                    Address paramAddr = program.getAddressFactory().getAddress(sp.add(BigInteger.valueOf(offset)).toString(16));
                    return readMemoryPointer(paramAddr, pointerSize);
                }
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_MIPS)) {
                // For MIPS, first 4 parameters are in registers a0-a3, then on stack
                if (paramIndex < 4) {
                    return emulator.readRegister("a" + paramIndex);
                } else {
                    // For params after a3, they're on the stack
                    BigInteger sp = emulator.readRegister("sp");
                    int offset = (paramIndex - 4) * pointerSize;
                    Address paramAddr = program.getAddressFactory().getAddress(sp.add(BigInteger.valueOf(offset)).toString(16));
                    return readMemoryPointer(paramAddr, pointerSize);
                }
            } else if (processor.equals(ArchitectureHelper.PROCESSOR_PPC)) {
                // For PowerPC, first 8 parameters are in registers r3-r10, then on stack
                if (paramIndex < 8) {
                    return emulator.readRegister("r" + (paramIndex + 3)); // r3 is param 0
                } else {
                    // For params after r10, they're on the stack
                    BigInteger sp = emulator.readRegister("r1"); // PowerPC SP is r1
                    int offset = (paramIndex - 8) * pointerSize;
                    Address paramAddr = program.getAddressFactory().getAddress(sp.add(BigInteger.valueOf(offset)).toString(16));
                    return readMemoryPointer(paramAddr, pointerSize);
                }
            }
            
            Msg.warn(this, "Parameter retrieval not implemented for " + processor);
            return null;
        } catch (Exception e) {
            Msg.warn(this, "Error reading function parameter " + paramIndex + ": " + e.getMessage());
            return null;
        }
    }
    
    /**
     * Helper method to read a memory pointer of specified size from an address.
     * 
     * @param address The memory address to read from
     * @param size The size in bytes of the pointer
     * @return The pointer value as a BigInteger
     */
    private BigInteger readMemoryPointer(Address address, int size) {
        try {
            byte[] bytes = new byte[size];
            for (int i = 0; i < size; i++) {
                bytes[i] = emulator.readMemoryByte(address.add(i));
            }
            return new BigInteger(bytesToHex(bytes), 16);
        } catch (Exception e) {
            Msg.warn(this, "Error reading memory pointer at " + address + ": " + e.getMessage());
            return BigInteger.ZERO;
        }
    }
    
    /**
     * Helper method to read a null-terminated string from memory.
     * 
     * @param addrBigInt The memory address as a BigInteger
     * @param maxLength Maximum length to read before truncating
     * @return The string read from memory
     */
    private String readStringFromMemory(BigInteger addrBigInt, int maxLength) {
        try {
            if (addrBigInt == null) {
                return "";
            }
            
            Address addr = program.getAddressFactory().getAddress(addrBigInt.toString(16));
            StringBuilder str = new StringBuilder();
            
            // Read up to maxLength characters, stopping at null terminator
            for (int i = 0; i < maxLength; i++) {
                byte b = emulator.readMemoryByte(addr.add(i));
                if (b == 0) {
                    break;
                }
                str.append((char) b);
            }
            
            return str.toString();
        } catch (Exception e) {
            Msg.warn(this, "Error reading string from memory: " + e.getMessage());
            return "";
        }
    }
    
    /**
     * Helper method to set a return value in the appropriate register
     * based on the processor architecture.
     * 
     * @param value The value to set
     */
    private void setReturnValue(long value) {
        try {
            String processor = archHelper.getProcessorName();

            switch (processor) {
                case ArchitectureHelper.PROCESSOR_X86:
                    // x86 return value is in EAX
                    emulator.writeRegister("EAX", BigInteger.valueOf(value));
                    break;
                case ArchitectureHelper.PROCESSOR_ARM:
                    // ARM return value is in R0
                    emulator.writeRegister("r0", BigInteger.valueOf(value));
                    break;
                case ArchitectureHelper.PROCESSOR_MIPS:
                    // MIPS return value is in V0
                    emulator.writeRegister("v0", BigInteger.valueOf(value));
                    break;
                case ArchitectureHelper.PROCESSOR_PPC:
                    // PowerPC return value is in R3
                    emulator.writeRegister("r3", BigInteger.valueOf(value));
                    break;
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
                return handlePrintf(false);
            } else if ("puts".equals(funcName)) {
                return handlePuts();
            } else if ("write".equals(funcName)) {
                return handleWrite();
            } else if ("putchar".equals(funcName) || "putc".equals(funcName)) {
                return handlePutChar();
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
                return handleFprintf();
            } else if ("perror".equals(funcName)) {
                return handlePerror();
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
                return handleScanf();
            } else if ("gets".equals(funcName) || "fgets".equals(funcName)) {
                return handleGets();
            } else if ("getchar".equals(funcName) || "getc".equals(funcName)) {
                return handleGetChar();
            } else if ("read".equals(funcName)) {
                boolean handled = handleRead();
                return handled;
            }
            
            // For other functions, just log that we encountered them
            Msg.info(this, "Unhandled stdin function: " + funcName);
        } catch (Exception e) {
            Msg.warn(this, "Error handling stdin function " + funcName + ": " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Handles printf function call.
     * 
     * @param isStderr Whether to output to stderr instead of stdout
     * @return true if handled successfully, false otherwise
     */
    private boolean handlePrintf(boolean isStderr) {
        try {
            // Get the format string parameter (first parameter)
            BigInteger formatPtr = readFunctionParameter(0);
            
            if (formatPtr != null) {
                // Read the format string from memory
                String formatStr = readStringFromMemory(formatPtr, 4096);
                
                // Parse the format string and substitute parameters
                String output = parseFormatString(formatStr, 1); // Start from parameter index 1
                
                // Output to the appropriate buffer
                if (isStderr) {
                    session.appendStderr(output);
                } else {
                    session.appendStdout(output);
                }
                
                // Return the length of the string output
                setReturnValue(output.length());
                return true;
            }
            return false;
        } catch (Exception e) {
            Msg.warn(this, "Error handling printf: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Handles puts function call.
     * 
     * @return true if handled successfully, false otherwise
     */
    private boolean handlePuts() {
        try {
            // Get pointer to the string (first parameter)
            BigInteger strPtr = readFunctionParameter(0);
            
            if (strPtr != null) {
                // Read the string from memory
                String str = readStringFromMemory(strPtr, 4096);
                
                // Output the string with a newline (puts adds a newline)
                String output = str + "\n";
                session.appendStdout(output);
                
                // Return success (puts returns a non-negative value on success)
                setReturnValue(1);
                return true;
            }
            return false;
        } catch (Exception e) {
            Msg.warn(this, "Error handling puts: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Handles putchar/putc function call.
     */
    private boolean handlePutChar() {
        try {
            // Get the character parameter (first parameter)
            BigInteger charValue = readFunctionParameter(0);
            
            if (charValue != null) {
                // Convert to char and output
                char ch = (char)(charValue.intValue() & 0xFF);
                session.appendStdout(String.valueOf(ch));
                
                // Return the character value
                setReturnValue(charValue.intValue() & 0xFF);
                return true;
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling putchar: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Handles fprintf function call.
     */
    private boolean handleFprintf() {
        try {
            // First parameter is FILE*
            BigInteger filePtr = readFunctionParameter(0);
            
            if (filePtr != null) {
                // In a real implementation, we'd need to check if this is stderr
                // For our purposes, we assume it's stderr since we can't easily check
                
                // Handle like printf but to stderr
                return handlePrintf(true);
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling fprintf: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Handles perror function call.
     */
    private boolean handlePerror() {
        try {
            // Get the error message parameter (first parameter)
            BigInteger msgPtr = readFunctionParameter(0);
            
            if (msgPtr != null) {
                // Read the message string from memory
                String msg = readStringFromMemory(msgPtr, 4096);
                
                // Output to stderr with "error" message
                String output = msg + ": Unknown error\n";
                session.appendStderr(output);
                
                return true;
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling perror: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Handles the write function call.
     */
    private boolean handleWrite() {
        try {
            // Get parameters for write(fd, buf, count)
            BigInteger fdBigInt = readFunctionParameter(0); // File descriptor
            BigInteger bufPtr = readFunctionParameter(1);   // Buffer address
            BigInteger count = readFunctionParameter(2);    // Number of bytes to write
            
            if (fdBigInt != null && bufPtr != null && count != null) {
                int fd = fdBigInt.intValue();
                int countInt = count.intValue();
                
                // Only handle stdout (1) and stderr (2)
                if (fd == STDOUT_FD || fd == STDERR_FD) {
                    // Read the buffer from memory
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
    
    /**
     * Handles scanf function call.
     */
    private boolean handleScanf() {
        try {
            // Get the format string parameter (first parameter)
            BigInteger formatPtr = readFunctionParameter(0);
            
            if (formatPtr != null) {
                // Read the format string from memory
                String formatStr = readStringFromMemory(formatPtr, 4096);
                
                // Read data from stdin
                String stdinData = session.readStdin(256); // Read a reasonable amount
                
                if (stdinData.isEmpty()) {
                    // No data available
                    setReturnValue(0);
                    return true;
                }
                
                // Process the format string to find specifiers
                int itemsProcessed = processScanfInput(formatStr, stdinData, 1);
                
                // Return number of items successfully processed
                setReturnValue(itemsProcessed);
                return true;
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling scanf: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Process scanf input and write values to memory locations.
     * This is a simplified implementation that handles some basic format specifiers.
     * 
     * @param formatStr The format string from scanf
     * @param input The input string to parse
     * @param paramStartIndex The starting index for output parameters
     * @return Number of items successfully processed
     */
    private int processScanfInput(String formatStr, String input, int paramStartIndex) {
        int itemsProcessed = 0;
        int paramIndex = paramStartIndex;
        
        // Very basic scanf parser - this could be substantially improved
        for (int i = 0; i < formatStr.length(); i++) {
            char c = formatStr.charAt(i);
            
            if (c == '%' && i + 1 < formatStr.length()) {
                char specifier = formatStr.charAt(i + 1);
                
                // Get the pointer to write the value to
                BigInteger destPtr = readFunctionParameter(paramIndex++);
                if (destPtr == null) {
                    continue;
                }
                
                // Create the destination address
                Address destAddr = program.getAddressFactory().getAddress(destPtr.toString(16));
                
                // Handle different format specifiers
                switch (specifier) {
                    case 'd':
                    case 'i':
                        // Integer format - find digits in input
                        try {
                            int startPos = findNextNonWhitespace(input, 0);
                            if (startPos >= 0) {
                                int endPos = findEndOfNumber(input, startPos);
                                if (endPos > startPos) {
                                    String numStr = input.substring(startPos, endPos);
                                    int value = Integer.parseInt(numStr);
                                    
                                    // Write integer to memory
                                    writeIntToMemory(destAddr, value);
                                    itemsProcessed++;
                                    
                                    // Update input
                                    input = input.substring(endPos);
                                }
                            }
                        } catch (Exception e) {
                            Msg.warn(this, "Error processing integer in scanf: " + e.getMessage());
                        }
                        break;
                        
                    case 's':
                        // String format - find string in input
                        try {
                            int startPos = findNextNonWhitespace(input, 0);
                            if (startPos >= 0) {
                                int endPos = findEndOfString(input, startPos);
                                if (endPos > startPos) {
                                    String str = input.substring(startPos, endPos);
                                    
                                    // Write string to memory with null terminator
                                    for (int j = 0; j < str.length(); j++) {
                                        emulator.writeMemory(destAddr.add(j), new byte[] { (byte)str.charAt(j) });
                                    }
                                    emulator.writeMemory(destAddr.add(str.length()), new byte[] { (byte)0 });
                                    itemsProcessed++;
                                    
                                    // Update input
                                    input = input.substring(endPos);
                                }
                            }
                        } catch (Exception e) {
                            Msg.warn(this, "Error processing string in scanf: " + e.getMessage());
                        }
                        break;
                    
                    // Could add more format specifiers here
                }
                
                i++; // Skip the specifier
            }
        }
        
        return itemsProcessed;
    }
    
    /**
     * Write an integer value to memory at the specified address.
     * 
     * @param address The address to write to
     * @param value The integer value to write
     */
    private void writeIntToMemory(Address address, int value) {
        try {
            byte[] bytes = new byte[4];
            // Write in little-endian order by default
            bytes[0] = (byte)(value & 0xFF);
            bytes[1] = (byte)((value >> 8) & 0xFF);
            bytes[2] = (byte)((value >> 16) & 0xFF);
            bytes[3] = (byte)((value >> 24) & 0xFF);
            
            // If big-endian, reverse the bytes
            if (archHelper.isBigEndian()) {
                byte temp = bytes[0];
                bytes[0] = bytes[3];
                bytes[3] = temp;
                
                temp = bytes[1];
                bytes[1] = bytes[2];
                bytes[2] = temp;
            }
            
            // Write the bytes to memory
            emulator.writeMemory(address, bytes);
        } catch (Exception e) {
            Msg.warn(this, "Error writing integer to memory: " + e.getMessage());
        }
    }
    
    /**
     * Find the index of the next non-whitespace character.
     * 
     * @param input The input string
     * @param startPos The starting position
     * @return The index of the next non-whitespace character, or -1 if not found
     */
    private int findNextNonWhitespace(String input, int startPos) {
        for (int i = startPos; i < input.length(); i++) {
            if (!Character.isWhitespace(input.charAt(i))) {
                return i;
            }
        }
        return -1;
    }
    
    /**
     * Find the end of a number in the input string.
     * 
     * @param input The input string
     * @param startPos The starting position (should be at a digit or sign)
     * @return The index after the end of the number
     */
    private int findEndOfNumber(String input, int startPos) {
        int i = startPos;
        
        // Handle optional sign
        if (i < input.length() && (input.charAt(i) == '+' || input.charAt(i) == '-')) {
            i++;
        }
        
        // Skip digits
        while (i < input.length() && Character.isDigit(input.charAt(i))) {
            i++;
        }
        
        return i;
    }
    
    /**
     * Find the end of a string in the input string.
     * A string ends at the first whitespace character.
     * 
     * @param input The input string
     * @param startPos The starting position
     * @return The index after the end of the string
     */
    private int findEndOfString(String input, int startPos) {
        for (int i = startPos; i < input.length(); i++) {
            if (Character.isWhitespace(input.charAt(i))) {
                return i;
            }
        }
        return input.length();
    }
    
    /**
     * Handles gets and fgets function calls.
     */
    private boolean handleGets() {
        try {
            // Get the buffer parameter (first parameter)
            BigInteger bufPtr = readFunctionParameter(0);
            
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
    
    /**
     * Handles getchar and getc function calls.
     */
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
    
    /**
     * Handles the read function call.
     */
    private boolean handleRead() {
        try {
            // Get parameters for read(fd, buf, count)
            BigInteger fdBigInt = readFunctionParameter(0); // File descriptor
            BigInteger bufPtr = readFunctionParameter(1);   // Buffer address
            BigInteger count = readFunctionParameter(2);    // Number of bytes to read
            
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
    
    /**
     * Handles system calls related to I/O.
     * 
     * @param op The p-code operation representing the system call (can be null)
     * @return true if handled, false otherwise
     */
    private boolean handleSyscall(PcodeOp op) {
        try {
            // Get the syscall number using the architecture helper
            int syscallNum = archHelper.getSyscallNumber();
            String processor = archHelper.getProcessorName();
            
            if (syscallNum != -1) {
                // Determine OS based on program format
                String os = SyscallMappings.determineOS(program);
                
                // Validate if the OS-architecture combination is supported
                if (!SyscallMappings.isSupported(os, processor)) {
                    Msg.warn(this, "Syscall handling may be limited for " + os + "/" + processor);
                }
                
                // Get overall list of syscalls for this OS/architecture to inform about support
                java.util.Map<Integer, SyscallMappings.SyscallInfo> allSyscalls = SyscallMappings.getAllSyscalls(os, processor);
                Msg.debug(this, "Syscall database has " + allSyscalls.size() + " entries for " + os + "/" + processor);
                
                // Get syscall information from SyscallMappings
                SyscallMappings.SyscallInfo syscallInfo = SyscallMappings.getSyscallInfo(os, processor, syscallNum);
                
                if (syscallInfo != null) {
                    String syscallName = syscallInfo.getName();
                    
                    // Avoid duplicate variable declarations
                    Msg.debug(this, "Handling syscall: " + syscallName + " (" + syscallNum + ") for OS: " + os + 
                               ", processor: " + processor + 
                               ", return: " + syscallInfo.getReturnType() + 
                               ", params: " + syscallInfo.getParamTypes().length);
                    
                    // Handle common I/O syscalls
                    switch (syscallName) {
                        case "exit":
                            // We can't actually exit, but we can report it
                            Msg.info(this, "Program requested exit via syscall");
                            return true;
                            
                        case "read":
                            return handleSyscallRead();
                            
                        case "write":
                            return handleSyscallWrite();
                            
                        case "open":
                        case "openat":
                            // Verify that this is indeed an I/O syscall using the mapping
                            boolean isIOConfirmed = SyscallMappings.isIOSyscall(os, processor, syscallNum);
                            if (isIOConfirmed) {
                                Msg.debug(this, "Handling confirmed I/O syscall: " + syscallName);
                            }
                            
                            // For now, just simulate success for open calls
                            setReturnValue(3); // Return a file descriptor
                            return true;
                            
                        case "close":
                            // Simulate success for close calls
                            setReturnValue(0);
                            return true;
                            
                        default:
                            // Get parameter count to help with debugging
                            int paramCount = SyscallMappings.getSyscallParamCount(os, processor, syscallNum);
                            String[] paramTypes = syscallInfo.getParamTypes();
                            String returnType = syscallInfo.getReturnType();
                            
                            // Check if this is an I/O syscall that we might want to handle specially
                            boolean isIO = SyscallMappings.isIOSyscall(os, processor, syscallNum);
                            
                            // Log with enhanced information
                            Msg.info(this, "Known but unhandled syscall: " + syscallName + 
                                    " (" + syscallNum + ") for " + os + "/" + processor +
                                    ", params: " + paramCount + 
                                    ", return: " + returnType +
                                    (isIO ? " [I/O Related]" : ""));
                            break;
                    }
                } else {
                    // Fall back to legacy handling if syscall is not found in our mappings
                    
                    // Linux x86/ARM syscalls
                    if (processor.equals(ArchitectureHelper.PROCESSOR_X86) || 
                        processor.equals(ArchitectureHelper.PROCESSOR_ARM)) {
                        
                        switch (syscallNum) {
                            case 1:  // exit
                                Msg.info(this, "Program requested exit via syscall");
                                return true;
                                
                            case 3:  // read
                                return handleSyscallRead();
                                
                            case 4:  // write
                                return handleSyscallWrite();
                        }
                    }
                    // MIPS syscalls
                    else if (processor.equals(ArchitectureHelper.PROCESSOR_MIPS)) {
                        switch (syscallNum) {
                            case 4001: // exit
                                Msg.info(this, "Program requested exit via syscall");
                                return true;
                                
                            case 4003: // read
                                return handleSyscallRead();
                                
                            case 4004: // write
                                return handleSyscallWrite();
                        }
                    }
                    
                    // Check if it's an I/O syscall even though it's not in our detailed mapping
                    boolean isIOSyscall = SyscallMappings.isIOSyscall(os, processor, syscallNum);
                    if (isIOSyscall) {
                        Msg.info(this, "Detected unknown I/O syscall: " + syscallNum + 
                               " for " + os + "/" + processor + " - handling generically");
                    } else {
                        Msg.info(this, "Unhandled syscall number: " + syscallNum + " for processor: " + processor);
                    }
                }
            } else {
                Msg.warn(this, "Could not determine syscall number for processor: " + processor);
            }
        } catch (Exception e) {
            Msg.warn(this, "Error handling syscall: " + e.getMessage());
        }
        
        return false;
    }
    
    /**
     * Handles the write syscall.
     */
    private boolean handleSyscallWrite() {
        try {
            String processor = archHelper.getProcessorName();
            
            // Get syscall information from SyscallMappings
            int syscallNum = archHelper.getSyscallNumber();
            SyscallMappings.SyscallInfo syscallInfo = SyscallMappings.getSyscallInfo(operatingSystem, processor, syscallNum);
            
            BigInteger fdBigInt;
            BigInteger bufPtr;
            BigInteger count;
            
            // Extract parameters based on processor architecture
            switch (processor) {
                case ArchitectureHelper.PROCESSOR_X86:
                    if (operatingSystem.equals(SyscallMappings.OS_LINUX)) {
                        // For x86 Linux, fd is in EBX, buf in ECX, count in EDX
                        fdBigInt = emulator.readRegister("EBX");
                        bufPtr = emulator.readRegister("ECX");
                        count = emulator.readRegister("EDX");
                    } else if (operatingSystem.equals(SyscallMappings.OS_MACOS)) {
                        // For macOS x86, parameters are different
                        fdBigInt = readFunctionParameter(0);
                        bufPtr = readFunctionParameter(1);
                        count = readFunctionParameter(2);
                    } else {
                        // Windows or other OS
                        Msg.warn(this, "Syscall write parameter retrieval not implemented for " + operatingSystem + " on " + processor);
                        return false;
                    }
                    break;
                case ArchitectureHelper.PROCESSOR_ARM:
                    // For ARM Linux/macOS, fd is in R0, buf in R1, count in R2
                    fdBigInt = emulator.readRegister("r0");
                    bufPtr = emulator.readRegister("r1");
                    count = emulator.readRegister("r2");
                    break;
                case ArchitectureHelper.PROCESSOR_MIPS:
                    // For MIPS Linux, fd is in A0, buf in A1, count in A2
                    fdBigInt = emulator.readRegister("a0");
                    bufPtr = emulator.readRegister("a1");
                    count = emulator.readRegister("a2");
                    break;
                case ArchitectureHelper.PROCESSOR_PPC:
                    // For PowerPC, fd is in R3, buf in R4, count in R5
                    fdBigInt = emulator.readRegister("r3");
                    bufPtr = emulator.readRegister("r4");
                    count = emulator.readRegister("r5");
                    break;
                default:
                    Msg.warn(this, "Syscall write parameter retrieval not implemented for " + processor);
                    return false;
            }
            
            if (fdBigInt != null && bufPtr != null && count != null) {
                int fd = fdBigInt.intValue();
                int countInt = count.intValue();
                
                // Only handle stdout (1) and stderr (2)
                if (fd == STDOUT_FD || fd == STDERR_FD) {
                    // Read the buffer
                    Address bufAddr = program.getAddressFactory().getAddress(bufPtr.toString(16));
                    
                    // Read safely with size limits
                    int safeCount = Math.min(countInt, 4096); // Limit to 4KB
                    StringBuilder str = new StringBuilder();
                    for (int i = 0; i < safeCount; i++) {
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
    
    /**
     * Handles the read syscall.
     */
    private boolean handleSyscallRead() {
        try {
            String processor = archHelper.getProcessorName();
            
            // Get syscall information from SyscallMappings
            int syscallNum = archHelper.getSyscallNumber();
            SyscallMappings.SyscallInfo syscallInfo = SyscallMappings.getSyscallInfo(operatingSystem, processor, syscallNum);
            
            BigInteger fdBigInt;
            BigInteger bufPtr;
            BigInteger count;
            
            // Extract parameters based on processor architecture and OS
            switch (processor) {
                case ArchitectureHelper.PROCESSOR_X86:
                    if (operatingSystem.equals(SyscallMappings.OS_LINUX)) {
                        // For x86 Linux, fd is in EBX, buf in ECX, count in EDX
                        fdBigInt = emulator.readRegister("EBX");
                        bufPtr = emulator.readRegister("ECX");
                        count = emulator.readRegister("EDX");
                    } else if (operatingSystem.equals(SyscallMappings.OS_MACOS)) {
                        // For macOS x86, parameters are different
                        fdBigInt = readFunctionParameter(0);
                        bufPtr = readFunctionParameter(1);
                        count = readFunctionParameter(2);
                    } else {
                        // Windows or other OS
                        Msg.warn(this, "Syscall read parameter retrieval not implemented for " + operatingSystem + " on " + processor);
                        return false;
                    }
                    break;
                case ArchitectureHelper.PROCESSOR_ARM:
                    // For ARM Linux/macOS, fd is in R0, buf in R1, count in R2
                    fdBigInt = emulator.readRegister("r0");
                    bufPtr = emulator.readRegister("r1");
                    count = emulator.readRegister("r2");
                    break;
                case ArchitectureHelper.PROCESSOR_MIPS:
                    // For MIPS Linux, fd is in A0, buf in A1, count in A2
                    fdBigInt = emulator.readRegister("a0");
                    bufPtr = emulator.readRegister("a1");
                    count = emulator.readRegister("a2");
                    break;
                case ArchitectureHelper.PROCESSOR_PPC:
                    // For PowerPC, fd is in R3, buf in R4, count in R5
                    fdBigInt = emulator.readRegister("r3");
                    bufPtr = emulator.readRegister("r4");
                    count = emulator.readRegister("r5");
                    break;
                default:
                    Msg.warn(this, "Syscall read parameter retrieval not implemented for " + processor);
                    return false;
            }
            
            if (fdBigInt != null && bufPtr != null && count != null) {
                int fd = fdBigInt.intValue();
                int countInt = count.intValue();
                
                // Only handle stdin (0)
                if (fd == STDIN_FD) {
                    // Read data from stdin buffer with safety limits
                    int safeCount = Math.min(countInt, 4096); // Limit to 4KB for safety
                    String input = session.readStdin(safeCount);
                    
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
     * Parse a format string and substitute arguments.
     * Handles basic format specifiers like %d, %s, %x, etc.
     * 
     * @param formatStr The format string to parse
     * @param paramStartIndex The starting index for parameter reading (typically 1 for printf)
     * @return The formatted output string
     */
    private String parseFormatString(String formatStr, int paramStartIndex) {
        if (formatStr == null || formatStr.isEmpty()) {
            return "";
        }
        
        StringBuilder result = new StringBuilder();
        int paramIndex = paramStartIndex;
        
        // Simple parser for format string
        for (int i = 0; i < formatStr.length(); i++) {
            char c = formatStr.charAt(i);
            
            if (c == '%' && i + 1 < formatStr.length()) {
                char specifier = formatStr.charAt(i + 1);
                
                // Handle format specifiers
                switch (specifier) {
                    case 'd':
                    case 'i':
                        // Integer format
                        BigInteger intValue = readFunctionParameter(paramIndex++);
                        if (intValue != null) {
                            result.append(intValue);
                        } else {
                            result.append("(null)");
                        }
                        i++; // Skip the specifier
                        break;
                        
                    case 'x':
                    case 'X':
                        // Hex format
                        BigInteger hexValue = readFunctionParameter(paramIndex++);
                        if (hexValue != null) {
                            result.append(hexValue.toString(16));
                        } else {
                            result.append("(null)");
                        }
                        i++; // Skip the specifier
                        break;
                        
                    case 's':
                        // String format
                        BigInteger strPtr = readFunctionParameter(paramIndex++);
                        if (strPtr != null) {
                            String str = readStringFromMemory(strPtr, 4096);
                            result.append(str);
                        } else {
                            result.append("(null)");
                        }
                        i++; // Skip the specifier
                        break;
                        
                    case 'c':
                        // Character format
                        BigInteger charValue = readFunctionParameter(paramIndex++);
                        if (charValue != null) {
                            result.append((char)(charValue.intValue() & 0xFF));
                        } else {
                            result.append("(null)");
                        }
                        i++; // Skip the specifier
                        break;
                        
                    case '%':
                        // Literal % character
                        result.append('%');
                        i++; // Skip the second %
                        break;
                        
                    default:
                        // Unsupported format, just keep as-is
                        result.append(c);
                        break;
                }
            } else {
                // Regular character, just append it
                result.append(c);
            }
        }
        
        return result.toString();
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
