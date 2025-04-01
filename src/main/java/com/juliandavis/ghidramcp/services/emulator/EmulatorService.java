package com.juliandavis.ghidramcp.services.emulator;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import com.juliandavis.ghidramcp.services.Service;
import com.juliandavis.ghidramcp.services.emulator.session.EmulatorSession;
import com.juliandavis.ArchitectureHelper;
import com.juliandavis.ghidramcp.emulation.syscall.SyscallMappings;
import com.juliandavis.StdioEmulationHelper;

/**
 * Service for managing emulation tasks in Ghidra using EmulatorHelper API.
 * This class provides methods for initializing an emulator, controlling execution,
 * and retrieving/manipulating the emulation state.
 */
public class EmulatorService implements Service {
    
    private static final String SERVICE_NAME = "EmulatorService";
    
    // Map to store emulator sessions by ID
    private final Map<String, EmulatorSession> emulatorSessions = new ConcurrentHashMap<>();
    
    // Counter for generating unique session IDs
    private final AtomicLong sessionCounter = new AtomicLong(0);
    
    // Current program for this service
    private Program program;
    
    /**
     * Get the service name
     * 
     * @return The service name
     */
    @Override
    public String getName() {
        return SERVICE_NAME;
    }
    
    /**
     * Initialize the service with a program
     * 
     * @param program The program to initialize with
     */
    @Override
    public void initialize(Program program) {
        this.program = program;
    }
    
    /**
     * Dispose of the service and clean up resources
     */
    @Override
    public void dispose() {
        // Close all sessions
        for (EmulatorSession session : emulatorSessions.values()) {
            session.dispose();
        }
        emulatorSessions.clear();
        this.program = null;
    }
    
    /**
     * Get the current program
     * 
     * @return The current program
     */
    public Program getProgram() {
        return program;
    }
    
    /**
     * Creates a new emulator session for the specified program.
     * 
     * @param program The program to emulate
     * @return A new EmulatorSession object
     */
    public EmulatorSession createSession(Program program) {
        // Create unique session ID
        String sessionId = "emulator_" + sessionCounter.incrementAndGet();
        
        // Create EmulatorHelper for the program
        EmulatorHelper emulator = new EmulatorHelper(program);
        
        // Create session object
        EmulatorSession session = new EmulatorSession(sessionId, emulator, program);
        
        // Store in session map
        emulatorSessions.put(sessionId, session);
        
        Msg.info(this, "Created emulator session: " + sessionId);
        return session;
    }
    
    /**
     * Retrieves an emulator session by ID.
     * 
     * @param sessionId The ID of the session to retrieve
     * @return The EmulatorSession object, or null if not found
     */
    public EmulatorSession getSession(String sessionId) {
        return emulatorSessions.get(sessionId);
    }
    
    /**
     * Disposes of an emulator session.
     * 
     * @param sessionId The ID of the session to dispose
     * @return true if the session was found and disposed, false otherwise
     */
    public boolean disposeSession(String sessionId) {
        EmulatorSession session = emulatorSessions.remove(sessionId);
        if (session != null) {
            session.dispose();
            Msg.info(this, "Disposed emulator session: " + sessionId);
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
    public boolean initializeEmulator(EmulatorSession session, String startAddressString, boolean writeTracking) {
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
            session.setupMemoryTracking(writeTracking);
            
            // Register the stdio emulation helper
            StdioEmulationHelper stdioHelper = new StdioEmulationHelper(session);
            stdioHelper.register();
            
            // Log information about syscall support for this binary
            Program program = session.getProgram(); // Get the program from the session
            ArchitectureHelper archHelper = new ArchitectureHelper(program, emulator);
            String os = SyscallMappings.determineOS(program);
            String processor = archHelper.getProcessorName();
            
            if (SyscallMappings.isOSSupported(os) && SyscallMappings.isSupported(os, processor)) {
                // Get all supported syscalls to log for debugging
                java.util.Map<Integer, SyscallMappings.SyscallInfo> allSyscalls = SyscallMappings.getAllSyscalls(os, processor);
                Msg.info(this, "Loaded " + allSyscalls.size() + " syscall mappings for " 
                        + os + "/" + processor);
            } else {
                Msg.warn(this, "Limited or no syscall support for " + os + "/" + processor);
            }

            // Initialize registers to reasonable defaults
            // Get architecture-specific register information
            String pcRegName = archHelper.getProgramCounterRegisterName();
            String spRegName = archHelper.getStackPointerRegisterName();
            
            session.initializeRegisters(pcRegName, spRegName, startAddress);
            
            session.clearState();
            session.setRunning(true);
            
            return true;
        } catch (Exception e) {
            Msg.error(this, "Error initializing emulator", e);
            session.setLastError("Error initializing emulator: " + e.getMessage());
            session.setRunning(false);
            return false;
        }
    }
    
    /**
     * Get the static instance of EmulatorService by implementating a singleton pattern.
     * This is primarily for backward compatibility.
     * 
     * @return The EmulatorService instance
     */
    private static EmulatorService instance;
    
    public static EmulatorService getInstance() {
        if (instance == null) {
            instance = new EmulatorService();
        }
        return instance;
    }
    
    public static void setInstance(EmulatorService service) {
        instance = service;
    }
}
