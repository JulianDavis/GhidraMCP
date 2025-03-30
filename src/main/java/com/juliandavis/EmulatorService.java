package com.juliandavis;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.emulator.MemoryAccessFilter;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.lang.Register;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Service for managing emulation tasks in Ghidra using EmulatorHelper API.
 * This class provides methods for initializing an emulator, controlling execution,
 * and retrieving/manipulating the emulation state.
 */
public class EmulatorService {
    
    // Map to store emulator sessions by ID
    private static final Map<String, EmulatorSession> emulatorSessions = new ConcurrentHashMap<>();
    
    // Counter for generating unique session IDs
    private static final AtomicLong sessionCounter = new AtomicLong(0);
    
    /**
     * Class representing an emulation session with state tracking
     */
    public static class EmulatorSession {
        private final String id;
        private final EmulatorHelper emulator;
        private final Program program;
        private final Set<Address> breakpoints;
        private final Map<String, String> conditionalBreakpoints;
        private final Map<Address, Byte> memoryWrites;
        private final Map<Address, Byte> memoryReads;
        private final Map<String, Long> registerWrites;
        private final List<Map<String, Object>> stackTrace;
        private Address startAddress;
        private Address currentAddress;
        private boolean running;
        private boolean trackMemoryReads;
        private boolean trackStackChanges;
        private String lastError;
        
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
            this.running = false;
            this.trackMemoryReads = false;
            this.trackStackChanges = false;
            this.lastError = null;
        }
        
        public String getId() {
            return id;
        }
        
        public EmulatorHelper getEmulator() {
            return emulator;
        }
        
        public Program getProgram() {
            return program;
        }
        
        public Address getStartAddress() {
            return startAddress;
        }
        
        public void setStartAddress(Address startAddress) {
            this.startAddress = startAddress;
            this.currentAddress = startAddress;
        }
        
        public Address getCurrentAddress() {
            return currentAddress;
        }
        
        public void setCurrentAddress(Address currentAddress) {
            this.currentAddress = currentAddress;
        }
        
        public boolean isRunning() {
            return running;
        }
        
        public void setRunning(boolean running) {
            this.running = running;
        }
        
        public String getLastError() {
            return lastError;
        }
        
        public void setLastError(String lastError) {
            this.lastError = lastError;
        }
        
        public Set<Address> getBreakpoints() {
            return Collections.unmodifiableSet(breakpoints);
        }
        
        public boolean addBreakpoint(Address address) {
            return breakpoints.add(address);
        }
        
        public boolean removeBreakpoint(Address address) {
            return breakpoints.remove(address);
        }
        
        public void clearBreakpoints() {
            breakpoints.clear();
        }
        
        public Map<Address, Byte> getMemoryWrites() {
            return Collections.unmodifiableMap(memoryWrites);
        }
        
        public void trackMemoryWrite(Address address, byte value) {
            memoryWrites.put(address, value);
        }
        
        public void trackMemoryWrite(Address address, byte[] bytes) {
            for (int i = 0; i < bytes.length; i++) {
                memoryWrites.put(address.add(i), bytes[i]);
            }
        }
        
        public Map<String, Long> getRegisterWrites() {
            return Collections.unmodifiableMap(registerWrites);
        }
        
        public void trackRegisterWrite(String registerName, long value) {
            registerWrites.put(registerName, value);
        }
        
        public boolean isTrackingMemoryReads() {
            return trackMemoryReads;
        }
        
        public void setTrackMemoryReads(boolean trackMemoryReads) {
            this.trackMemoryReads = trackMemoryReads;
        }
        
        public boolean isTrackingStackChanges() {
            return trackStackChanges;
        }
        
        public void setTrackStackChanges(boolean trackStackChanges) {
            this.trackStackChanges = trackStackChanges;
        }
        
        public Map<Address, Byte> getMemoryReads() {
            return Collections.unmodifiableMap(memoryReads);
        }
        
        public void trackMemoryRead(Address address, byte value) {
            if (trackMemoryReads) {
                memoryReads.put(address, value);
            }
        }
        
        public void trackMemoryRead(Address address, byte[] bytes) {
            if (trackMemoryReads) {
                for (int i = 0; i < bytes.length; i++) {
                    memoryReads.put(address.add(i), bytes[i]);
                }
            }
        }
        
        public Map<String, String> getConditionalBreakpoints() {
            return Collections.unmodifiableMap(conditionalBreakpoints);
        }
        
        public void addConditionalBreakpoint(Address address, String condition) {
            conditionalBreakpoints.put(address.toString(), condition);
        }
        
        public boolean removeConditionalBreakpoint(Address address) {
            return conditionalBreakpoints.remove(address.toString()) != null;
        }
        
        public List<Map<String, Object>> getStackTrace() {
            return Collections.unmodifiableList(stackTrace);
        }
        
        public void addStackFrame(Map<String, Object> frame) {
            if (trackStackChanges) {
                stackTrace.add(frame);
            }
        }
        
        public void clearState() {
            memoryWrites.clear();
            memoryReads.clear();
            registerWrites.clear();
            stackTrace.clear();
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
    
    /**
     * Creates a new emulator session for the specified program.
     * 
     * @param program The program to emulate
     * @return A new EmulatorSession object
     */
    public static EmulatorSession createSession(Program program) {
        // Create unique session ID
        String sessionId = "emulator_" + sessionCounter.incrementAndGet();
        
        // Create EmulatorHelper for the program
        EmulatorHelper emulator = new EmulatorHelper(program);
        
        // Create session object
        EmulatorSession session = new EmulatorSession(sessionId, emulator, program);
        
        // Store in session map
        emulatorSessions.put(sessionId, session);
        
        Msg.info(EmulatorService.class, "Created emulator session: " + sessionId);
        return session;
    }
    
    /**
     * Retrieves an emulator session by ID.
     * 
     * @param sessionId The ID of the session to retrieve
     * @return The EmulatorSession object, or null if not found
     */
    public static EmulatorSession getSession(String sessionId) {
        return emulatorSessions.get(sessionId);
    }
    
    /**
     * Disposes of an emulator session.
     * 
     * @param sessionId The ID of the session to dispose
     * @return true if the session was found and disposed, false otherwise
     */
    public static boolean disposeSession(String sessionId) {
        EmulatorSession session = emulatorSessions.remove(sessionId);
        if (session != null) {
            session.dispose();
            Msg.info(EmulatorService.class, "Disposed emulator session: " + sessionId);
            return true;
        }
        return false;
    }
    
    /**
     * Initializes an emulator session at the specified address.
     * 
     * @param session The emulator session to initialize
     * @param startAddressString The address to start emulation from (as a string)
     * @param writeTracking Whether to enable write tracking
     * @return true if initialization successful, false otherwise
     */
    public static boolean initializeEmulator(EmulatorSession session, String startAddressString, boolean writeTracking) {
        if (session == null) {
            return false;
        }
        
        try {
            // Get start address
            Address startAddress = session.getProgram().getAddressFactory().getAddress(startAddressString);
            if (startAddress == null) {
                session.setLastError("Invalid start address: " + startAddressString);
                return false;
            }
            
            session.setStartAddress(startAddress);
            session.setCurrentAddress(startAddress);
            
            // Configure the emulator
            EmulatorHelper emulator = session.getEmulator();
            
            // Register a memory access filter if tracking is enabled
            emulator.getEmulator().addMemoryAccessFilter(new MemoryAccessFilter() {
                @Override
                protected void processRead(AddressSpace space, long offset, int size, byte[] values) {
                    // Track memory reads when enabled
                    if (session.isTrackingMemoryReads() && values != null) {
                        // Convert AddressSpace and offset to an Address object
                        Address address = space.getAddress(offset);
                        session.trackMemoryRead(address, values);
                    }
                }
                
                @Override
                protected void processWrite(AddressSpace space, long offset, int size, byte[] values) {
                    // Track memory writes when enabled
                    if (writeTracking && values != null) {
                        // Convert AddressSpace and offset to an Address object
                        Address address = space.getAddress(offset);
                        session.trackMemoryWrite(address, values);
                    }
                }
            });

            // Initialize registers to reasonable defaults
            // Set default register values using writeRegister
            // Get architecture-specific register information
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), emulator);
            String pcRegName = archHelper.getProgramCounterRegisterName();
            String spRegName = archHelper.getStackPointerRegisterName();
            
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
                    Msg.debug(EmulatorService.class, "Could not initialize register: " + reg.getName());
                }
            }
            
            // Set the program counter to the start address using the architecture helper we created above
            emulator.writeRegister(pcRegName, startAddress.getOffset());
            
            session.clearState();
            session.setRunning(true);
            
            return true;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error initializing emulator", e);
            session.setLastError("Error initializing emulator: " + e.getMessage());
            session.setRunning(false);
            return false;
        }
    }
    
    /**
     * Steps the emulator forward by a single instruction.
     * 
     * @param session The emulator session
     * @return Map containing the result status and new program counter state
     */
    public static Map<String, Object> stepEmulator(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        if (!session.isRunning()) {
            result.put("success", false);
            result.put("error", "Emulator is not running");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Get architecture helper
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), emulator);
            
            // Get the current program counter
            String pcRegisterName = archHelper.getProgramCounterRegisterName();
            Address currentPC = session.getProgram().getAddressFactory().getAddress(
                    emulator.readRegister(pcRegisterName).toString(16));
            
            // Step the emulator
            boolean stepped = emulator.step(TaskMonitor.DUMMY);
            
            // Read the new program counter
            Address newPC = session.getProgram().getAddressFactory().getAddress(
                    emulator.readRegister(pcRegisterName).toString(16));
            
            session.setCurrentAddress(newPC);
            
            if (!stepped) {
                session.setRunning(false);
                session.setLastError("Emulator step failed");
                result.put("success", false);
                result.put("error", "Emulator step failed");
                return result;
            }
            
            // Track all register changes
            List<Register> registers = emulator.getProgram().getLanguage().getRegisters();
            for (Register reg : registers) {
                try {
                    String regName = reg.getName();
                    session.trackRegisterWrite(regName, emulator.readRegister(regName).longValue());
                } catch (Exception e) {
                    // Some registers may not be readable; just skip them
                }
            }
            
            // Track stack changes if enabled
            if (session.isTrackingStackChanges()) {
                trackStackChanges(session, currentPC);
            }
            
            result.put("success", true);
            result.put("previousPC", currentPC.toString());
            result.put("newPC", newPC.toString());
            
            // Get the instruction that was executed
            try {
                result.put("instruction", session.getProgram().getListing().getInstructionAt(currentPC).toString());
            } catch (Exception e) {
                result.put("instruction", "Unknown");
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error stepping emulator", e);
            session.setLastError("Error stepping emulator: " + e.getMessage());
            session.setRunning(false);
            result.put("success", false);
            result.put("error", e.getMessage());
            return result;
        }
    }
    
    /**
     * Runs the emulator until a specified condition is met.
     * 
     * @param session The emulator session
     * @param maxSteps Maximum number of steps to run (to prevent infinite loops)
     * @param stopOnBreakpoint Whether to stop at breakpoints
     * @param stopAddressStr Optional specific address to stop at (can be null)
     * @return Map containing the result of the run operation
     */
    public static Map<String, Object> runEmulator(EmulatorSession session, int maxSteps, 
                                                boolean stopOnBreakpoint, String stopAddressStr) {
        Map<String, Object> result = new HashMap<>();
        List<Map<String, Object>> executedInstructions = new ArrayList<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        if (!session.isRunning()) {
            result.put("success", false);
            result.put("error", "Emulator is not running");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Address stopAddress = null;
            
            // Parse stop address if provided
            if (stopAddressStr != null && !stopAddressStr.isEmpty()) {
                stopAddress = session.getProgram().getAddressFactory().getAddress(stopAddressStr);
            }
            
            // Use architecture helper for processor-specific register names
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), emulator);
            String pcRegisterName = archHelper.getProgramCounterRegisterName();
            int stepCount = 0;
            boolean hitBreakpoint = false;
            boolean reachedStopAddress = false;
            
            // Execute steps until condition is met
            while (stepCount < maxSteps) {
                // Get current PC before step
                Address currentPC = session.getProgram().getAddressFactory().getAddress(
                        emulator.readRegister(pcRegisterName).toString(16));
                
                // Check for regular breakpoint before stepping
                if (stopOnBreakpoint && session.getBreakpoints().contains(currentPC)) {
                    hitBreakpoint = true;
                    result.put("breakpointType", "normal");
                    break;
                }
                
                // Check for conditional breakpoint before stepping
                if (stopOnBreakpoint && session.getConditionalBreakpoints().containsKey(currentPC.toString())) {
                    String condition = session.getConditionalBreakpoints().get(currentPC.toString());
                    boolean conditionMet = evaluateBreakpointCondition(session, condition);
                    
                    if (conditionMet) {
                        hitBreakpoint = true;
                        result.put("breakpointType", "conditional");
                        result.put("condition", condition);
                        break;
                    }
                }
                
                // Check for stop address before stepping
                if (stopAddress != null && currentPC.equals(stopAddress)) {
                    reachedStopAddress = true;
                    break;
                }
                
                // Step the emulator
                boolean stepped = emulator.step(TaskMonitor.DUMMY);
                
                // Read the new program counter
                Address newPC = session.getProgram().getAddressFactory().getAddress(
                        emulator.readRegister(pcRegisterName).toString(16));
                
                session.setCurrentAddress(newPC);
                
                if (!stepped) {
                    session.setLastError("Emulator step failed during run at step " + stepCount);
                    result.put("success", false);
                    result.put("error", "Emulator step failed during run at step " + stepCount);
                    result.put("stepsExecuted", stepCount);
                    result.put("executedInstructions", executedInstructions);
                    return result;
                }
                
                // Track register changes
                List<Register> registers = emulator.getProgram().getLanguage().getRegisters();
                for (Register reg : registers) {
                    try {
                        String regName = reg.getName();
                        session.trackRegisterWrite(regName, emulator.readRegister(regName).longValue());
                    } catch (Exception e) {
                        // Some registers may not be readable; just skip them
                    }
                }
                
                // Track stack changes if enabled
                if (session.isTrackingStackChanges()) {
                    trackStackChanges(session, currentPC);
                }
                
                // Record executed instruction
                Map<String, Object> instrInfo = new HashMap<>();
                instrInfo.put("address", currentPC.toString());
                try {
                    instrInfo.put("instruction", session.getProgram().getListing().getInstructionAt(currentPC).toString());
                } catch (Exception e) {
                    instrInfo.put("instruction", "Unknown");
                }
                executedInstructions.add(instrInfo);
                
                stepCount++;
            }
            
            result.put("success", true);
            result.put("stepsExecuted", stepCount);
            result.put("executedInstructions", executedInstructions);
            result.put("currentPC", session.getCurrentAddress().toString());
            
            if (hitBreakpoint) {
                result.put("stoppedReason", "breakpoint");
                result.put("breakpointAddress", session.getCurrentAddress().toString());
            } else if (reachedStopAddress) {
                result.put("stoppedReason", "targetAddress");
            } else if (stepCount >= maxSteps) {
                result.put("stoppedReason", "maxStepsReached");
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error running emulator", e);
            session.setLastError("Error running emulator: " + e.getMessage());
            session.setRunning(false);
            result.put("success", false);
            result.put("error", e.getMessage());
            result.put("stepsExecuted", executedInstructions.size());
            result.put("executedInstructions", executedInstructions);
            return result;
        }
    }
    
    /**
     * Retrieves the current emulation state.
     * 
     * @param session The emulator session
     * @return Map containing the registers and memory state
     */
    public static Map<String, Object> getEmulatorState(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Map<String, Object> registerState = new HashMap<>();
            
            // Get all register values
            for (Register reg : emulator.getProgram().getLanguage().getRegisters()) {
                try {
                    String regName = reg.getName();
                    BigInteger value = emulator.readRegister(regName);
                    registerState.put(regName, value.toString(16));
                } catch (Exception e) {
                    // Skip registers that can't be read
                }
            }
            
            // Get PC as a special case for convenience
            String pcRegisterName = emulator.getPCRegister().getName();
            BigInteger pcValue = emulator.readRegister(pcRegisterName);
            Address pcAddress = session.getProgram().getAddressFactory().getAddress(pcValue.toString(16));
            
            // Extract memory state (focusing on modified memory)
            Map<String, Object> memoryState = new HashMap<>();
            if (!session.getMemoryWrites().isEmpty()) {
                // Group contiguous memory writes
                SortedMap<Address, byte[]> contiguousWrites = groupContiguousWrites(session.getMemoryWrites());
                
                for (Map.Entry<Address, byte[]> entry : contiguousWrites.entrySet()) {
                    Address addr = entry.getKey();
                    byte[] bytes = entry.getValue();
                    
                    StringBuilder hexString = new StringBuilder();
                    for (byte b : bytes) {
                        hexString.append(String.format("%02x", b));
                    }
                    
                    memoryState.put(addr.toString(), hexString.toString());
                }
            }
            
            result.put("success", true);
            result.put("registers", registerState);
            result.put("programCounter", pcAddress.toString());
            result.put("memory", memoryState);
            result.put("status", session.isRunning() ? "running" : "stopped");
            
            if (session.getLastError() != null) {
                result.put("lastError", session.getLastError());
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error getting emulator state", e);
            result.put("success", false);
            result.put("error", "Error getting emulator state: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Groups contiguous memory writes into byte arrays.
     * 
     * @param memoryWrites Map of individual memory writes
     * @return Map of starting addresses to byte arrays
     */
    private static SortedMap<Address, byte[]> groupContiguousWrites(Map<Address, Byte> memoryWrites) {
        TreeMap<Address, byte[]> result = new TreeMap<>();
        
        if (memoryWrites.isEmpty()) {
            return result;
        }
        
        // Sort addresses
        List<Address> addresses = new ArrayList<>(memoryWrites.keySet());
        Collections.sort(addresses);
        
        Address startAddress = addresses.get(0);
        List<Byte> currentGroup = new ArrayList<>();
        currentGroup.add(memoryWrites.get(startAddress));
        
        for (int i = 1; i < addresses.size(); i++) {
            Address prevAddr = addresses.get(i-1);
            Address currAddr = addresses.get(i);
            
            // Check if addresses are contiguous
            if (currAddr.equals(prevAddr.add(1))) {
                // Continue current group
                currentGroup.add(memoryWrites.get(currAddr));
            } else {
                // Finish current group and start a new one
                byte[] bytes = new byte[currentGroup.size()];
                for (int j = 0; j < currentGroup.size(); j++) {
                    bytes[j] = currentGroup.get(j);
                }
                result.put(startAddress, bytes);
                
                // Start new group
                startAddress = currAddr;
                currentGroup.clear();
                currentGroup.add(memoryWrites.get(currAddr));
            }
        }
        
        // Add the last group
        if (!currentGroup.isEmpty()) {
            byte[] bytes = new byte[currentGroup.size()];
            for (int j = 0; j < currentGroup.size(); j++) {
                bytes[j] = currentGroup.get(j);
            }
            result.put(startAddress, bytes);
        }
        
        return result;
    }
    
    /**
     * Gets a list of memory locations that were written during emulation.
     * 
     * @param session The emulator session
     * @return Map containing the list of memory writes
     */
    public static Map<String, Object> getMemoryWrites(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            List<Map<String, Object>> writes = new ArrayList<>();
            
            // Group contiguous memory writes
            SortedMap<Address, byte[]> contiguousWrites = groupContiguousWrites(session.getMemoryWrites());
            
            for (Map.Entry<Address, byte[]> entry : contiguousWrites.entrySet()) {
                Address addr = entry.getKey();
                byte[] bytes = entry.getValue();
                
                Map<String, Object> writeInfo = new HashMap<>();
                writeInfo.put("address", addr.toString());
                writeInfo.put("length", bytes.length);
                
                StringBuilder hexString = new StringBuilder();
                StringBuilder asciiString = new StringBuilder();
                
                for (byte b : bytes) {
                    hexString.append(String.format("%02x", b));
                    
                    // Add ASCII representation if printable
                    if (b >= 32 && b < 127) {
                        asciiString.append((char) b);
                    } else {
                        asciiString.append('.');
                    }
                }
                
                writeInfo.put("hexValue", hexString.toString());
                writeInfo.put("asciiValue", asciiString.toString());
                writes.add(writeInfo);
            }
            
            result.put("success", true);
            result.put("writes", writes);
            result.put("count", writes.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error getting memory writes", e);
            result.put("success", false);
            result.put("error", "Error getting memory writes: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Writes memory bytes from emulator to Ghidra program.
     * 
     * @param session The emulator session
     * @param fromAddressStr Starting address to import (as string)
     * @param lengthStr Length of bytes to import (as string)
     * @return Map containing the result of the import operation
     */
    public static Map<String, Object> importMemoryToProgram(EmulatorSession session, String fromAddressStr, String lengthStr) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Parse parameters
            Address fromAddress = program.getAddressFactory().getAddress(fromAddressStr);
            int length = Integer.parseInt(lengthStr);
            
            if (fromAddress == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + fromAddressStr);
                return result;
            }
            
            if (length <= 0) {
                result.put("success", false);
                result.put("error", "Invalid length: " + lengthStr);
                return result;
            }
            
            // Read memory from emulator
            byte[] bytes = new byte[length];
            for (int i = 0; i < length; i++) {
                Address addr = fromAddress.add(i);
                try {
                    bytes[i] = emulator.readMemoryByte(addr);
                } catch (Exception e) {
                    Msg.warn(EmulatorService.class, "Failed to read byte at " + addr + ": " + e.getMessage());
                    bytes[i] = 0;
                }
            }
            
            // Write memory to program
            int transactionID = program.startTransaction("Import memory from emulator");
            boolean success = false;
            
            try {
                Memory memory = program.getMemory();
                
                // Check if the memory range is writeable
                boolean canWrite = true;
                for (int i = 0; i < length; i++) {
                    Address addr = fromAddress.add(i);
                    MemoryBlock block = memory.getBlock(addr);
                    if (block == null || !block.isWrite()) {
                        canWrite = false;
                        break;
                    }
                }
                
                if (!canWrite) {
                    throw new MemoryAccessException("Memory range is not writeable");
                }
                
                // Write the bytes
                memory.setBytes(fromAddress, bytes);
                success = true;
                
                result.put("success", true);
                result.put("bytesWritten", length);
                result.put("fromAddress", fromAddress.toString());
                result.put("toAddress", fromAddress.add(length - 1).toString());
                
            } catch (Exception e) {
                Msg.error(EmulatorService.class, "Error writing memory to program", e);
                result.put("success", false);
                result.put("error", "Error writing memory to program: " + e.getMessage());
            } finally {
                program.endTransaction(transactionID, success);
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error importing memory", e);
            result.put("success", false);
            result.put("error", "Error importing memory: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Sets a breakpoint at the specified address.
     * 
     * @param session The emulator session
     * @param addressStr The address to set the breakpoint at (as a string)
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> setBreakpoint(EmulatorSession session, String addressStr) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            Program program = session.getProgram();
            Address address = program.getAddressFactory().getAddress(addressStr);
            
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            boolean added = session.addBreakpoint(address);
            
            result.put("success", true);
            result.put("address", address.toString());
            result.put("added", added);
            if (!added) {
                result.put("message", "Breakpoint already exists at this address");
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error setting breakpoint", e);
            result.put("success", false);
            result.put("error", "Error setting breakpoint: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Clears a breakpoint at the specified address.
     * 
     * @param session The emulator session
     * @param addressStr The address to clear the breakpoint from (as a string)
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> clearBreakpoint(EmulatorSession session, String addressStr) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            Program program = session.getProgram();
            Address address = program.getAddressFactory().getAddress(addressStr);
            
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            boolean removed = session.removeBreakpoint(address);
            
            result.put("success", true);
            result.put("address", address.toString());
            result.put("removed", removed);
            if (!removed) {
                result.put("message", "No breakpoint exists at this address");
            }
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error clearing breakpoint", e);
            result.put("success", false);
            result.put("error", "Error clearing breakpoint: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets a list of all active breakpoints.
     * 
     * @param session The emulator session
     * @return Map containing the list of breakpoints
     */
    public static Map<String, Object> getBreakpoints(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            List<String> breakpoints = new ArrayList<>();
            
            for (Address address : session.getBreakpoints()) {
                breakpoints.add(address.toString());
            }
            
            result.put("success", true);
            result.put("breakpoints", breakpoints);
            result.put("count", breakpoints.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error getting breakpoints", e);
            result.put("success", false);
            result.put("error", "Error getting breakpoints: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Tracks stack changes for the current instruction
     * 
     * @param session The emulator session
     * @param instructionAddress The address of the current instruction
     */
    private static void trackStackChanges(EmulatorSession session, Address instructionAddress) {
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Get architecture-specific information
            ArchitectureHelper archHelper = new ArchitectureHelper(program, emulator);
            
            // Get stack pointer value using architecture helper
            String spRegName = archHelper.getStackPointerRegisterName();
            if (spRegName == null) {
                Msg.warn(EmulatorService.class, "Could not determine stack pointer register");
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
            
            // Try to read some values from the stack
            Address stackAddr = program.getAddressFactory().getAddress(spValue.toString(16));
            List<Map<String, Object>> stackValues = new ArrayList<>();
            
            // Get pointer size for this architecture
            int pointerSize = archHelper.getPointerSize();
            
            // Read up to 8 stack values
            for (int i = 0; i < 8; i++) {
                try {
                    byte[] bytes = new byte[pointerSize];
                    for (int j = 0; j < bytes.length; j++) {
                        bytes[j] = emulator.readMemoryByte(stackAddr.add(i * pointerSize + j));
                    }
                    
                    Map<String, Object> entry = new HashMap<>();
                    entry.put("offset", i * pointerSize);
                    
                    // Convert to hex string
                    StringBuilder hexValue = new StringBuilder();
                    for (byte b : bytes) {
                        hexValue.append(String.format("%02x", b));
                    }
                    entry.put("value", "0x" + hexValue.toString());
                    
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
            Msg.error(EmulatorService.class, "Error tracking stack changes", e);
        }
    }
    
    /**
     * Evaluates a conditional breakpoint expression
     * 
     * @param session The emulator session
     * @param condition The condition expression to evaluate
     * @return true if the condition is met, false otherwise
     */
    private static boolean evaluateBreakpointCondition(EmulatorSession session, String condition) {
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Simple condition format: REG=VALUE or REG!=VALUE
            if (condition.contains("=") || condition.contains("!=") || 
                condition.contains("<") || condition.contains(">")) {
                
                // Try to split the condition into register and value
                String operation = null;
                String[] parts = null;
                
                if (condition.contains("!=")) {
                    operation = "!=";
                    parts = condition.split("!=");
                } else if (condition.contains("<=")) {
                    operation = "<=";
                    parts = condition.split("<=");
                } else if (condition.contains(">=")) {
                    operation = ">=";
                    parts = condition.split(">=");
                } else if (condition.contains("=")) {
                    operation = "=";
                    parts = condition.split("=");
                } else if (condition.contains("<")) {
                    operation = "<";
                    parts = condition.split("<");
                } else if (condition.contains(">")) {
                    operation = ">";
                    parts = condition.split(">");
                }
                
                if (parts != null && parts.length == 2) {
                    String regName = parts[0].trim();
                    String valueStr = parts[1].trim();
                    
                    // Handle hex values
                    long compareValue;
                    if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
                        compareValue = Long.parseLong(valueStr.substring(2), 16);
                    } else {
                        compareValue = Long.parseLong(valueStr);
                    }
                    
                    // Get register value
                    BigInteger regValue = emulator.readRegister(regName);
                    
                    if (regValue != null) {
                        switch (operation) {
                            case "=":
                                return regValue.longValue() == compareValue;
                            case "!=":
                                return regValue.longValue() != compareValue;
                            case "<":
                                return regValue.longValue() < compareValue;
                            case ">":
                                return regValue.longValue() > compareValue;
                            case "<=":
                                return regValue.longValue() <= compareValue;
                            case ">=":
                                return regValue.longValue() >= compareValue;
                        }
                    }
                }
            }
            
            // Memory conditions: MEM[addr]=value
            if (condition.contains("MEM[") && condition.contains("]=")) {
                int startIdx = condition.indexOf("MEM[") + 4;
                int endIdx = condition.indexOf("]", startIdx);
                
                if (startIdx > 4 && endIdx > startIdx) {
                    String addrStr = condition.substring(startIdx, endIdx).trim();
                    Address addr = session.getProgram().getAddressFactory().getAddress(addrStr);
                    
                    if (addr != null) {
                        // Extract the expected value
                        String valueStr = condition.substring(condition.indexOf("]=") + 2).trim();
                        
                        // Handle hex values
                        long compareValue;
                        if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
                            compareValue = Long.parseLong(valueStr.substring(2), 16);
                        } else {
                            compareValue = Long.parseLong(valueStr);
                        }
                        
                        // Read memory value
                        try {
                            byte memValue = emulator.readMemoryByte(addr);
                            return (memValue & 0xFF) == (compareValue & 0xFF);
                        } catch (Exception e) {
                            Msg.warn(EmulatorService.class, "Cannot read memory at " + addr + ": " + e.getMessage());
                        }
                    }
                }
            }
            
            // Add more condition types as needed
            
            return false;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error evaluating breakpoint condition: " + condition, e);
            return false;
        }
    }
    
    /**
     * Sets the value of a specific register in the emulator.
     * 
     * @param session The emulator session
     * @param registerName The name of the register to modify
     * @param valueStr The value to set as a string (decimal or hex)
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> setRegisterValue(EmulatorSession session, String registerName, String valueStr) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Parse the value (handle hex or decimal)
            BigInteger value;
            if (valueStr.startsWith("0x") || valueStr.startsWith("0X")) {
                value = new BigInteger(valueStr.substring(2), 16);
            } else {
                value = new BigInteger(valueStr);
            }
            
            // Write the register value
            emulator.writeRegister(registerName, value);
            
            // Track the write
            session.trackRegisterWrite(registerName, value.longValue());
            
            result.put("success", true);
            result.put("register", registerName);
            result.put("value", value.toString(16));
            result.put("decimal", value.toString());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error setting register value", e);
            result.put("success", false);
            result.put("error", "Error setting register value: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets the value of a specific register from the emulator.
     * 
     * @param session The emulator session
     * @param registerName The name of the register to read
     * @return Map containing the register value
     */
    public static Map<String, Object> getRegisterValue(EmulatorSession session, String registerName) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Read the register value
            BigInteger value = emulator.readRegister(registerName);
            
            result.put("success", true);
            result.put("register", registerName);
            result.put("value", value.toString(16));
            result.put("decimal", value.toString());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error getting register value", e);
            result.put("success", false);
            result.put("error", "Error getting register value: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets a list of all available registers in the emulator.
     * 
     * @param session The emulator session
     * @return Map containing the list of register names
     */
    public static Map<String, Object> getRegisterNames(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            
            // Get register names
            List<Register> registers = emulator.getProgram().getLanguage().getRegisters();
            
            // Create a list of register info with values
            List<Map<String, Object>> registerList = new ArrayList<>();
            for (Register reg : registers) {
                try {
                    String regName = reg.getName();
                    BigInteger value = emulator.readRegister(regName);
                    
                    Map<String, Object> regInfo = new HashMap<>();
                    regInfo.put("name", regName);
                    regInfo.put("value", value.toString(16));
                    
                    // Add special markers for PC, SP, etc.
                    if (reg.equals(emulator.getPCRegister())) {
                        regInfo.put("isPC", true);
                    }
                    if (reg.equals(emulator.getStackPointerRegister())) {
                        regInfo.put("isSP", true);
                    }
                    
                    registerList.add(regInfo);
                } catch (Exception e) {
                    // Skip registers that can't be read
                }
            }
            
            result.put("success", true);
            result.put("registers", registerList);
            result.put("count", registerList.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error getting register names", e);
            result.put("success", false);
            result.put("error", "Error getting register names: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Writes bytes to a specified memory address in the emulator.
     * 
     * @param session The emulator session
     * @param addressStr The address to write to (as a string)
     * @param bytesHex The bytes to write (as a hex string)
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> writeMemory(EmulatorSession session, String addressStr, String bytesHex) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Parse address
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            // Parse hex bytes
            if (bytesHex.length() % 2 != 0) {
                result.put("success", false);
                result.put("error", "Invalid hex string: length must be even");
                return result;
            }
            
            byte[] bytes = new byte[bytesHex.length() / 2];
            for (int i = 0; i < bytes.length; i++) {
                int index = i * 2;
                bytes[i] = (byte) Integer.parseInt(bytesHex.substring(index, index + 2), 16);
            }
            
            // Write memory
            emulator.writeMemory(address, bytes);
            
            // Track the write (already tracked by filter if enabled)
            if (!session.isTrackingMemoryReads()) {
                session.trackMemoryWrite(address, bytes);
            }
            
            result.put("success", true);
            result.put("address", address.toString());
            result.put("bytesWritten", bytes.length);
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error writing memory", e);
            result.put("success", false);
            result.put("error", "Error writing memory: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Reads bytes from a specified memory address in the emulator.
     * 
     * @param session The emulator session
     * @param addressStr The address to read from (as a string)
     * @param length The number of bytes to read
     * @return Map containing the bytes read
     */
    public static Map<String, Object> readMemory(EmulatorSession session, String addressStr, int length) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        if (length <= 0 || length > 4096) {
            result.put("success", false);
            result.put("error", "Invalid length: " + length + ". Must be between 1 and 4096.");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Program program = session.getProgram();
            
            // Parse address
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            // Read memory
            byte[] bytes = new byte[length];
            for (int i = 0; i < length; i++) {
                bytes[i] = emulator.readMemoryByte(address.add(i));
            }
            
            // Track the read if enabled
            if (session.isTrackingMemoryReads()) {
                session.trackMemoryRead(address, bytes);
            }
            
            // Format the bytes
            StringBuilder hexString = new StringBuilder();
            StringBuilder asciiString = new StringBuilder();
            
            for (byte b : bytes) {
                hexString.append(String.format("%02x", b));
                
                // Add ASCII representation if printable
                if (b >= 32 && b < 127) {
                    asciiString.append((char) b);
                } else {
                    asciiString.append('.');
                }
            }
            
            result.put("success", true);
            result.put("address", address.toString());
            result.put("length", length);
            result.put("hexValue", hexString.toString());
            result.put("asciiValue", asciiString.toString());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error reading memory", e);
            result.put("success", false);
            result.put("error", "Error reading memory: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Sets a conditional breakpoint at the specified address.
     * 
     * @param session The emulator session
     * @param addressStr The address to set the breakpoint at (as a string)
     * @param condition The condition expression for the breakpoint
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> setConditionalBreakpoint(EmulatorSession session, String addressStr, String condition) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            Program program = session.getProgram();
            Address address = program.getAddressFactory().getAddress(addressStr);
            
            if (address == null) {
                result.put("success", false);
                result.put("error", "Invalid address: " + addressStr);
                return result;
            }
            
            // Add the conditional breakpoint
            session.addConditionalBreakpoint(address, condition);
            
            result.put("success", true);
            result.put("address", address.toString());
            result.put("condition", condition);
            result.put("message", "Conditional breakpoint set at " + address.toString());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error setting conditional breakpoint", e);
            result.put("success", false);
            result.put("error", "Error setting conditional breakpoint: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets a list of all conditional breakpoints.
     * 
     * @param session The emulator session
     * @return Map containing the list of conditional breakpoints
     */
    public static Map<String, Object> getConditionalBreakpoints(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            Map<String, String> conditionalBreakpoints = session.getConditionalBreakpoints();
            List<Map<String, Object>> breakpoints = new ArrayList<>();
            
            for (Map.Entry<String, String> entry : conditionalBreakpoints.entrySet()) {
                Map<String, Object> bp = new HashMap<>();
                bp.put("address", entry.getKey());
                bp.put("condition", entry.getValue());
                breakpoints.add(bp);
            }
            
            result.put("success", true);
            result.put("breakpoints", breakpoints);
            result.put("count", breakpoints.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error getting conditional breakpoints", e);
            result.put("success", false);
            result.put("error", "Error getting conditional breakpoints: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Enables or disables memory read tracking in the emulator.
     * 
     * @param session The emulator session
     * @param enable Whether to enable or disable memory read tracking
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> setMemoryReadTracking(EmulatorSession session, boolean enable) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            session.setTrackMemoryReads(enable);
            
            result.put("success", true);
            result.put("tracking", enable);
            result.put("message", "Memory read tracking " + (enable ? "enabled" : "disabled"));
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error setting memory read tracking", e);
            result.put("success", false);
            result.put("error", "Error setting memory read tracking: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Enables or disables stack change tracking in the emulator.
     * 
     * @param session The emulator session
     * @param enable Whether to enable or disable stack change tracking
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> setStackChangeTracking(EmulatorSession session, boolean enable) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            session.setTrackStackChanges(enable);
            
            result.put("success", true);
            result.put("tracking", enable);
            result.put("message", "Stack change tracking " + (enable ? "enabled" : "disabled"));
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error setting stack change tracking", e);
            result.put("success", false);
            result.put("error", "Error setting stack change tracking: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets memory read data from the emulator.
     * 
     * @param session The emulator session
     * @return Map containing the list of memory reads
     */
    public static Map<String, Object> getMemoryReads(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            if (!session.isTrackingMemoryReads()) {
                result.put("success", false);
                result.put("error", "Memory read tracking is not enabled");
                return result;
            }
            
            List<Map<String, Object>> reads = new ArrayList<>();
            
            // Group contiguous memory reads
            SortedMap<Address, byte[]> contiguousReads = groupContiguousWrites(session.getMemoryReads());
            
            for (Map.Entry<Address, byte[]> entry : contiguousReads.entrySet()) {
                Address addr = entry.getKey();
                byte[] bytes = entry.getValue();
                
                Map<String, Object> readInfo = new HashMap<>();
                readInfo.put("address", addr.toString());
                readInfo.put("length", bytes.length);
                
                StringBuilder hexString = new StringBuilder();
                StringBuilder asciiString = new StringBuilder();
                
                for (byte b : bytes) {
                    hexString.append(String.format("%02x", b));
                    
                    // Add ASCII representation if printable
                    if (b >= 32 && b < 127) {
                        asciiString.append((char) b);
                    } else {
                        asciiString.append('.');
                    }
                }
                
                readInfo.put("hexValue", hexString.toString());
                readInfo.put("asciiValue", asciiString.toString());
                reads.add(readInfo);
            }
            
            result.put("success", true);
            result.put("reads", reads);
            result.put("count", reads.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error getting memory reads", e);
            result.put("success", false);
            result.put("error", "Error getting memory reads: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Gets the stack trace from the emulator.
     * 
     * @param session The emulator session
     * @return Map containing the stack trace
     */
    public static Map<String, Object> getStackTrace(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            if (!session.isTrackingStackChanges()) {
                result.put("success", false);
                result.put("error", "Stack change tracking is not enabled");
                return result;
            }
            
            List<Map<String, Object>> stackTrace = session.getStackTrace();
            
            result.put("success", true);
            result.put("stackTrace", stackTrace);
            result.put("count", stackTrace.size());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error getting stack trace", e);
            result.put("success", false);
            result.put("error", "Error getting stack trace: " + e.getMessage());
            return result;
        }
    }
    
    /**
     * Resets the emulator to its initial state.
     * 
     * @param session The emulator session
     * @return Map containing the result of the operation
     */
    public static Map<String, Object> resetEmulator(EmulatorSession session) {
        Map<String, Object> result = new HashMap<>();
        
        if (session == null) {
            result.put("success", false);
            result.put("error", "Invalid session");
            return result;
        }
        
        try {
            EmulatorHelper emulator = session.getEmulator();
            Address startAddress = session.getStartAddress();
            
            if (startAddress == null) {
                result.put("success", false);
                result.put("error", "Emulator has not been initialized with a start address");
                return result;
            }
            
            // Reset registers to default values
            // Get architecture-specific register information
            ArchitectureHelper archHelper = new ArchitectureHelper(session.getProgram(), emulator);
            String pcRegName = archHelper.getProgramCounterRegisterName();
            String spRegName = archHelper.getStackPointerRegisterName();
            
            // Set default register values using writeRegister
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
                    Msg.debug(EmulatorService.class, "Could not reset register: " + reg.getName());
                }
            }
            
            // Set PC back to start address using architecture helper
            String pcRegisterName = archHelper.getProgramCounterRegisterName();
            emulator.writeRegister(pcRegisterName, startAddress.getOffset());
            
            // Clear state tracking
            session.clearState();
            session.setCurrentAddress(startAddress);
            session.setRunning(true);
            session.setLastError(null);
            
            result.put("success", true);
            result.put("message", "Emulator reset to initial state");
            result.put("programCounter", startAddress.toString());
            
            return result;
        } catch (Exception e) {
            Msg.error(EmulatorService.class, "Error resetting emulator", e);
            result.put("success", false);
            result.put("error", "Error resetting emulator: " + e.getMessage());
            return result;
        }
    }
}