package com.juliandavis.ghidramcp.emulation.core;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.util.*;

/**
 * Represents a single emulation session with state tracking.
 * Each session maintains its own state including registers, memory, and breakpoints.
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
    private boolean running;
    private boolean trackMemoryReads;
    private boolean trackStackChanges;
    private String lastError;
    
    /**
     * Creates a new emulator session with the specified ID, emulator, and program.
     * 
     * @param id The unique identifier for this session
     * @param emulator The EmulatorHelper instance
     * @param program The program being emulated
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
     * Gets the unique identifier for this session.
     * 
     * @return The session ID
     */
    public String getId() {
        return id;
    }
    
    /**
     * Gets the EmulatorHelper instance for this session.
     * 
     * @return The EmulatorHelper
     */
    public EmulatorHelper getEmulator() {
        return emulator;
    }
    
    /**
     * Gets the program being emulated.
     * 
     * @return The Program
     */
    public Program getProgram() {
        return program;
    }
    
    /**
     * Gets the starting address for emulation.
     * 
     * @return The start address
     */
    public Address getStartAddress() {
        return startAddress;
    }
    
    /**
     * Sets the starting address for emulation.
     * 
     * @param startAddress The start address
     */
    public void setStartAddress(Address startAddress) {
        this.startAddress = startAddress;
    }

    /**
     * Checks if the emulator is running.
     * 
     * @return true if running, false otherwise
     */
    public boolean isRunning() {
        return running;
    }
    
    /**
     * Sets the running state of the emulator.
     * 
     * @param running The running state
     */
    public void setRunning(boolean running) {
        this.running = running;
    }
    
    /**
     * Gets the last error that occurred during emulation.
     * 
     * @return The last error message, or null if no error
     */
    public String getLastError() {
        return lastError;
    }
    
    /**
     * Sets the last error message.
     * 
     * @param lastError The error message
     */
    public void setLastError(String lastError) {
        this.lastError = lastError;
    }
    
    /**
     * Gets the set of active breakpoints.
     * 
     * @return An unmodifiable set of breakpoint addresses
     */
    public Set<Address> getBreakpoints() {
        return Collections.unmodifiableSet(breakpoints);
    }
    
    /**
     * Adds a breakpoint at the specified address.
     * 
     * @param address The address to set the breakpoint at
     * @return true if the breakpoint was added, false if it already existed
     */
    public boolean addBreakpoint(Address address) {
        return breakpoints.add(address);
    }
    
    /**
     * Removes a breakpoint at the specified address.
     * 
     * @param address The address to remove the breakpoint from
     * @return true if the breakpoint was removed, false if it didn't exist
     */
    public boolean removeBreakpoint(Address address) {
        return breakpoints.remove(address);
    }
    
    /**
     * Clears all breakpoints.
     */
    public void clearBreakpoints() {
        breakpoints.clear();
    }
    
    /**
     * Gets the map of memory writes that occurred during emulation.
     * 
     * @return An unmodifiable map of address to byte value
     */
    public Map<Address, Byte> getMemoryWrites() {
        return Collections.unmodifiableMap(memoryWrites);
    }
    
    /**
     * Tracks a memory write at the specified address.
     * 
     * @param address The address where the write occurred
     * @param value The byte value written
     */
    public void trackMemoryWrite(Address address, byte value) {
        memoryWrites.put(address, value);
    }
    
    /**
     * Tracks multiple memory writes starting at the specified address.
     * 
     * @param address The starting address where the writes occurred
     * @param bytes The byte values written
     */
    public void trackMemoryWrite(Address address, byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            memoryWrites.put(address.add(i), bytes[i]);
        }
    }
    
    /**
     * Gets the map of register writes that occurred during emulation.
     * 
     * @return An unmodifiable map of register name to value
     */
    public Map<String, Long> getRegisterWrites() {
        return Collections.unmodifiableMap(registerWrites);
    }
    
    /**
     * Tracks a register write.
     * 
     * @param registerName The name of the register
     * @param value The value written
     */
    public void trackRegisterWrite(String registerName, long value) {
        registerWrites.put(registerName, value);
    }
    
    /**
     * Checks if memory read tracking is enabled.
     * 
     * @return true if tracking is enabled, false otherwise
     */
    public boolean isTrackingMemoryReads() {
        return trackMemoryReads;
    }
    
    /**
     * Enables or disables memory read tracking.
     * 
     * @param trackMemoryReads true to enable tracking, false to disable
     */
    public void setTrackMemoryReads(boolean trackMemoryReads) {
        this.trackMemoryReads = trackMemoryReads;
    }
    
    /**
     * Checks if stack change tracking is enabled.
     * 
     * @return true if tracking is enabled, false otherwise
     */
    public boolean isTrackingStackChanges() {
        return trackStackChanges;
    }
    
    /**
     * Enables or disables stack change tracking.
     * 
     * @param trackStackChanges true to enable tracking, false to disable
     */
    public void setTrackStackChanges(boolean trackStackChanges) {
        this.trackStackChanges = trackStackChanges;
    }
    
    /**
     * Gets the map of memory reads that occurred during emulation.
     * 
     * @return An unmodifiable map of address to byte value
     */
    public Map<Address, Byte> getMemoryReads() {
        return Collections.unmodifiableMap(memoryReads);
    }
    
    /**
     * Tracks a memory read at the specified address.
     * 
     * @param address The address where the read occurred
     * @param value The byte value read
     */
    public void trackMemoryRead(Address address, byte value) {
        if (trackMemoryReads) {
            memoryReads.put(address, value);
        }
    }
    
    /**
     * Tracks multiple memory reads starting at the specified address.
     * 
     * @param address The starting address where the reads occurred
     * @param bytes The byte values read
     */
    public void trackMemoryRead(Address address, byte[] bytes) {
        if (trackMemoryReads) {
            for (int i = 0; i < bytes.length; i++) {
                memoryReads.put(address.add(i), bytes[i]);
            }
        }
    }
    
    /**
     * Gets the map of conditional breakpoints.
     * 
     * @return An unmodifiable map of address string to condition expression
     */
    public Map<String, String> getConditionalBreakpoints() {
        return Collections.unmodifiableMap(conditionalBreakpoints);
    }
    
    /**
     * Adds a conditional breakpoint at the specified address.
     * 
     * @param address The address to set the breakpoint at
     * @param condition The condition expression
     */
    public void addConditionalBreakpoint(Address address, String condition) {
        conditionalBreakpoints.put(address.toString(), condition);
    }
    
    /**
     * Removes a conditional breakpoint at the specified address.
     * 
     * @param address The address to remove the breakpoint from
     * @return true if the breakpoint was removed, false if it didn't exist
     */
    public boolean removeConditionalBreakpoint(Address address) {
        return conditionalBreakpoints.remove(address.toString()) != null;
    }
    
    /**
     * Gets the stack trace that was collected during emulation.
     * 
     * @return An unmodifiable list of stack frames
     */
    public List<Map<String, Object>> getStackTrace() {
        return Collections.unmodifiableList(stackTrace);
    }
    
    /**
     * Adds a stack frame to the stack trace.
     * 
     * @param frame The stack frame to add
     */
    public void addStackFrame(Map<String, Object> frame) {
        if (trackStackChanges) {
            stackTrace.add(frame);
        }
    }
    
    /**
     * Clears all state tracking information.
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
     * Gets the current content of the stdout buffer.
     * 
     * @return The captured stdout content
     */
    public String getStdoutContent() {
        return stdoutBuffer.toString();
    }
    
    /**
     * Gets the current content of the stderr buffer.
     * 
     * @return The captured stderr content
     */
    public String getStderrContent() {
        return stderrBuffer.toString();
    }
    
    /**
     * Gets the current content of the stdin buffer.
     * 
     * @return The current stdin content
     */
    public String getStdinContent() {
        return stdinBuffer.toString();
    }
    
    /**
     * Appends data to the stdout buffer.
     * 
     * @param data The data to append to stdout
     */
    public void appendStdout(String data) {
        stdoutBuffer.append(data);
    }
    
    /**
     * Appends data to the stderr buffer.
     * 
     * @param data The data to append to stderr
     */
    public void appendStderr(String data) {
        stderrBuffer.append(data);
    }
    
    /**
     * Provides input data to the stdin buffer.
     * 
     * @param data The data to add to stdin
     */
    public void provideStdinData(String data) {
        stdinBuffer.append(data);
    }
    
    /**
     * Reads characters from the stdin buffer up to maxChars.
     * 
     * @param maxChars Maximum number of characters to read
     * @return The read characters
     */
    public String readStdin(int maxChars) {
        if (stdinBuffer.isEmpty()) {
            return "";
        }
        
        int charsToRead = Math.min(maxChars, stdinBuffer.length());
        String result = stdinBuffer.substring(0, charsToRead);
        stdinBuffer.delete(0, charsToRead);
        return result;
    }
    
    /**
     * Clean up resources associated with this session.
     */
    public void dispose() {
        if (emulator != null) {
            emulator.dispose();
        }
    }
}