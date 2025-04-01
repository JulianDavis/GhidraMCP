package com.juliandavis.ghidramcp.services.emulator.session;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.emulator.MemoryAccessFilter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.math.BigInteger;
import java.util.*;

/**
 * Class representing an emulation session with state tracking
 */
public class EmulatorSession {
    private final String id;
    private final EmulatorHelper emulator;
    private final Program program;
    private final Set<Address> breakpoints;
    private final Map<String, String> conditionalBreakpoints;
    private final Map<Address, Byte> memoryWrites;
    private final Map<Address, Byte> memoryReads;
    private final Map<String, Long> registerWrites;
    private final List<Map<String, Object>> stackTrace;
    private final StringBuilder stdoutBuffer;
    private final StringBuilder stderrBuffer;
    private final StringBuilder stdinBuffer;
    private Address startAddress;
    private Address currentAddress;
    private boolean running;
    private boolean trackMemoryReads;
    private boolean trackStackChanges;
    private String lastError;
    
    /**
     * Create a new emulator session
     * 
     * @param id The session ID
     * @param emulator The EmulatorHelper instance
     * @param program The Program instance
     */
    public EmulatorSession(String id, EmulatorHelper emulator, Program program) {
        this.id = id;
        this.emulator = emulator;
        this.program = program;
        this.breakpoints = new HashSet<>();
        this.conditionalBreakpoints = new HashMap<>();
        this.memoryWrites = new HashMap<>();
        this.memoryReads = new HashMap<>();
        this.registerWrites = new HashMap<>();
        this.stackTrace = new ArrayList<>();
        this.stdoutBuffer = new StringBuilder();
        this.stderrBuffer = new StringBuilder();
        this.stdinBuffer = new StringBuilder();
        this.running = false;
        this.trackMemoryReads = false;
        this.trackStackChanges = false;
        this.lastError = null;
    }
    
    /**
     * Get the session ID
     * 
     * @return The session ID
     */
    public String getId() {
        return id;
    }
    
    /**
     * Get the EmulatorHelper instance
     * 
     * @return The EmulatorHelper instance
     */
    public EmulatorHelper getEmulator() {
        return emulator;
    }
    
    /**
     * Get the Program instance
     * 
     * @return The Program instance
     */
    public Program getProgram() {
        return program;
    }
    
    /**
     * Get the start address
     * 
     * @return The start address
     */
    public Address getStartAddress() {
        return startAddress;
    }
    
    /**
     * Set the start address
     * 
     * @param startAddress The start address
     */
    public void setStartAddress(Address startAddress) {
        this.startAddress = startAddress;
        this.currentAddress = startAddress;
    }
    
    /**
     * Get the current address
     * 
     * @return The current address
     */
    public Address getCurrentAddress() {
        return currentAddress;
    }
    
    /**
     * Set the current address
     * 
     * @param currentAddress The current address
     */
    public void setCurrentAddress(Address currentAddress) {
        this.currentAddress = currentAddress;
    }
    
    /**
     * Check if the emulator is running
     * 
     * @return true if running, false otherwise
     */
    public boolean isRunning() {
        return running;
    }
    
    /**
     * Set the running state
     * 
     * @param running The running state
     */
    public void setRunning(boolean running) {
        this.running = running;
    }
    
    /**
     * Get the last error
     * 
     * @return The last error
     */
    public String getLastError() {
        return lastError;
    }
    
    /**
     * Set the last error
     * 
     * @param lastError The last error
     */
    public void setLastError(String lastError) {
        this.lastError = lastError;
    }
    
    /**
     * Get the breakpoints
     * 
     * @return The breakpoints
     */
    public Set<Address> getBreakpoints() {
        return Collections.unmodifiableSet(breakpoints);
    }
    
    /**
     * Add a breakpoint
     * 
     * @param address The address to add a breakpoint at
     * @return true if the breakpoint was added, false if it already existed
     */
    public boolean addBreakpoint(Address address) {
        return breakpoints.add(address);
    }
    
    /**
     * Remove a breakpoint
     * 
     * @param address The address to remove a breakpoint from
     * @return true if the breakpoint was removed, false if it didn't exist
     */
    public boolean removeBreakpoint(Address address) {
        return breakpoints.remove(address);
    }
    
    /**
     * Clear all breakpoints
     */
    public void clearBreakpoints() {
        breakpoints.clear();
    }
    
    /**
     * Get memory writes
     * 
     * @return The memory writes
     */
    public Map<Address, Byte> getMemoryWrites() {
        return Collections.unmodifiableMap(memoryWrites);
    }
    
    /**
     * Track a memory write
     * 
     * @param address The address of the write
     * @param value The value written
     */
    public void trackMemoryWrite(Address address, byte value) {
        memoryWrites.put(address, value);
    }
    
    /**
     * Track a memory write
     * 
     * @param address The address of the write
     * @param bytes The bytes written
     */
    public void trackMemoryWrite(Address address, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            memoryWrites.put(address.add(i), bytes[i]);
        }
    }
    
    /**
     * Get register writes
     * 
     * @return The register writes
     */
    public Map<String, Long> getRegisterWrites() {
        return Collections.unmodifiableMap(registerWrites);
    }
    
    /**
     * Track a register write
     * 
     * @param registerName The register name
     * @param value The value written
     */
    public void trackRegisterWrite(String registerName, long value) {
        registerWrites.put(registerName, value);
    }
    
    /**
     * Check if memory reads are being tracked
     * 
     * @return true if memory reads are being tracked, false otherwise
     */
    public boolean isTrackingMemoryReads() {
        return trackMemoryReads;
    }
    
    /**
     * Set memory read tracking
     * 
     * @param trackMemoryReads Whether to track memory reads
     */
    public void setTrackMemoryReads(boolean trackMemoryReads) {
        this.trackMemoryReads = trackMemoryReads;
    }
    
    /**
     * Check if stack changes are being tracked
     * 
     * @return true if stack changes are being tracked, false otherwise
     */
    public boolean isTrackingStackChanges() {
        return trackStackChanges;
    }
    
    /**
     * Set stack change tracking
     * 
     * @param trackStackChanges Whether to track stack changes
     */
    public void setTrackStackChanges(boolean trackStackChanges) {
        this.trackStackChanges = trackStackChanges;
    }
    
    /**
     * Get memory reads
     * 
     * @return The memory reads
     */
    public Map<Address, Byte> getMemoryReads() {
        return Collections.unmodifiableMap(memoryReads);
    }
    
    /**
     * Track a memory read
     * 
     * @param address The address of the read
     * @param value The value read
     */
    public void trackMemoryRead(Address address, byte value) {
        if (trackMemoryReads) {
            memoryReads.put(address, value);
        }
    }
    
    /**
     * Track a memory read
     * 
     * @param address The address of the read
     * @param bytes The bytes read
     */
    public void trackMemoryRead(Address address, byte[] bytes) {
        if (trackMemoryReads) {
            for (int i = 0; i < bytes.length; i++) {
                memoryReads.put(address.add(i), bytes[i]);
            }
        }
    }
    
    /**
     * Get conditional breakpoints
     * 
     * @return The conditional breakpoints
     */
    public Map<String, String> getConditionalBreakpoints() {
        return Collections.unmodifiableMap(conditionalBreakpoints);
    }
    
    /**
     * Add a conditional breakpoint
     * 
     * @param address The address to add the breakpoint at
     * @param condition The condition expression
     */
    public void addConditionalBreakpoint(Address address, String condition) {
        conditionalBreakpoints.put(address.toString(), condition);
    }
    
    /**
     * Remove a conditional breakpoint
     * 
     * @param address The address to remove the breakpoint from
     * @return true if the breakpoint was removed, false if it didn't exist
     */
    public boolean removeConditionalBreakpoint(Address address) {
        return conditionalBreakpoints.remove(address.toString()) != null;
    }
    
    /**
     * Get the stack trace
     * 
     * @return The stack trace
     */
    public List<Map<String, Object>> getStackTrace() {
        return Collections.unmodifiableList(stackTrace);
    }
    
    /**
     * Add a stack frame
     * 
     * @param frame The stack frame to add
     */
    public void addStackFrame(Map<String, Object> frame) {
        if (trackStackChanges) {
            stackTrace.add(frame);
        }
    }
    
    /**
     * Clear session state
     */
    public void clearState() {
        memoryWrites.clear();
        memoryReads.clear();
        registerWrites.clear();
        stackTrace.clear();
        stdoutBuffer.setLength(0);
        stderrBuffer.setLength(0);
        stdinBuffer.setLength(0);
    }
    
    /**
     * Gets the current content of the stdout buffer
     * 
     * @return The captured stdout content
     */
    public String getStdoutContent() {
        return stdoutBuffer.toString();
    }
    
    /**
     * Gets the current content of the stderr buffer
     * 
     * @return The captured stderr content
     */
    public String getStderrContent() {
        return stderrBuffer.toString();
    }
    
    /**
     * Gets the current content of the stdin buffer
     * 
     * @return The current stdin content
     */
    public String getStdinContent() {
        return stdinBuffer.toString();
    }
    
    /**
     * Appends data to the stdout buffer
     * 
     * @param data The data to append to stdout
     */
    public void appendStdout(String data) {
        stdoutBuffer.append(data);
    }
    
    /**
     * Appends data to the stderr buffer
     * 
     * @param data The data to append to stderr
     */
    public void appendStderr(String data) {
        stderrBuffer.append(data);
    }
    
    /**
     * Provides input data to the stdin buffer
     * 
     * @param data The data to add to stdin
     */
    public void provideStdinData(String data) {
        stdinBuffer.append(data);
    }
    
    /**
     * Reads characters from the stdin buffer up to maxChars
     * 
     * @param maxChars Maximum number of characters to read
     * @return The read characters
     */
    public String readStdin(int maxChars) {
        if (stdinBuffer.length() == 0) {
            return "";
        }
        
        int charsToRead = Math.min(maxChars, stdinBuffer.length());
        String result = stdinBuffer.substring(0, charsToRead);
        stdinBuffer.delete(0, charsToRead);
        return result;
    }
    
    /**
     * Set up memory tracking for the emulator
     * 
     * @param writeTracking Whether to enable write tracking
     */
    public void setupMemoryTracking(boolean writeTracking) {
        // Register a memory access filter if tracking is enabled
        getEmulator().getEmulator().addMemoryAccessFilter(new MemoryAccessFilter() {
            @Override
            protected void processRead(AddressSpace space, long offset, int size, byte[] values) {
                // Track memory reads when enabled
                if (isTrackingMemoryReads() && values != null) {
                    // Convert AddressSpace and offset to an Address object
                    Address address = space.getAddress(offset);
                    trackMemoryRead(address, values);
                }
            }
            
            @Override
            protected void processWrite(AddressSpace space, long offset, int size, byte[] values) {
                // Track memory writes when enabled
                if (writeTracking && values != null) {
                    // Convert AddressSpace and offset to an Address object
                    Address address = space.getAddress(offset);
                    trackMemoryWrite(address, values);
                }
            }
        });
    }
    
    /**
     * Initialize registers to reasonable defaults
     * 
     * @param pcRegName Program counter register name
     * @param spRegName Stack pointer register name
     * @param startAddress The start address
     */
    public void initializeRegisters(String pcRegName, String spRegName, Address startAddress) {
        try {
            EmulatorHelper emulator = getEmulator();
            
            List<Register> registers = emulator.getProgram().getLanguage().getRegisters();
            for (Register reg : registers) {
                try {
                    String regName = reg.getName();
                    // Only set non-special registers to avoid conflicts
                    if (!regName.equals(pcRegName) && !regName.equals(spRegName)) {
                        // Use 0 as a default value for most registers
                        emulator.writeRegister(reg, BigInteger.ZERO);
                    }
                } catch (Exception e) {
                    // Some registers may not be writable; just skip them
                    Msg.debug(this, "Could not initialize register: " + reg.getName());
                }
            }
            
            // Set the program counter to the start address
            emulator.writeRegister(pcRegName, startAddress.getOffset());
        } catch (Exception e) {
            Msg.error(this, "Error initializing registers", e);
            setLastError("Error initializing registers: " + e.getMessage());
        }
    }
    
    /**
     * Clean up resources associated with this session
     */
    public void dispose() {
        if (emulator != null) {
            emulator.dispose();
        }
    }
}
