package com.juliandavis.ghidramcp.emulation.syscall;

import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.util.Msg;

import java.util.HashMap;
import java.util.Map;

import com.juliandavis.ghidramcp.emulation.arch.ArchitectureHelper;

/**
 * Helper class to map operating system specific syscall numbers to their names and information.
 * This provides comprehensive syscall information for different OS/architecture combinations
 * to support emulation and analysis.
 */
public class SyscallMappings {
    
    // Define OS types
    public static final String OS_LINUX = "linux";
    public static final String OS_MACOS = "macos";
    public static final String OS_WINDOWS = "windows";
    
    // Define binary format types
    public static final String FORMAT_ELF = "ELF";
    public static final String FORMAT_PE = "PE";
    public static final String FORMAT_MACHO = "MACH-O";
    
    // Storage for all mappings, indexed by "os_processor"
    private static final Map<String, Map<Integer, SyscallInfo>> SYSCALL_MAPS = new HashMap<>();
    
    // Initialize the mappings
    static {
        // Initialize Linux syscalls for multiple architectures
        initLinuxX86Syscalls();
        initLinuxX8664Syscalls();
        initLinuxARMSyscalls();
        initLinuxARM64Syscalls();
        initLinuxMIPSSyscalls();
        initLinuxPPCSyscalls();
        
        // Initialize macOS syscalls
        initMacOSX86Syscalls();
        initMacOSX8664Syscalls();
        initMacOSARMSyscalls();
        
        // Initialize Windows syscalls
        initWindowsX86Syscalls();
        initWindowsX8664Syscalls();
    }

    /**
         * Represents information about a system call
         * Contains details about the syscall name, parameters, return type, etc.
         */
        public record SyscallInfo(String name, int paramCount, String[] paramTypes, String returnType, String description) {
        /**
         * Creates a new syscall information object
         *
         * @param name        The name of the syscall
         * @param paramCount  The number of parameters the syscall takes
         * @param paramTypes  Array of parameter type strings
         * @param returnType  The return type of the syscall
         * @param description A brief description of what the syscall does
         */
        public SyscallInfo {
        }

        @Override
            public String toString() {
                StringBuilder sb = new StringBuilder();
                sb.append(returnType).append(" ").append(name).append("(");

            for (int i = 0; i < paramTypes.length; i++) {
                    sb.append(paramTypes[i]);
                    if (i < paramTypes.length - 1) {
                        sb.append(", ");
                    }
                }

            sb.append(") - ").append(description);
                return sb.toString();
            }
        }
    
    /**
     * Initialize Linux x86 (32-bit) syscalls
     */
    private static void initLinuxX86Syscalls() {
        Map<Integer, SyscallInfo> syscalls = new HashMap<>();
        
        // Core I/O syscalls
        syscalls.put(1, new SyscallInfo("exit", 1, 
                        new String[]{"int"}, "void", "Terminate the process"));
        syscalls.put(2, new SyscallInfo("fork", 0, 
                        new String[]{}, "pid_t", "Create a child process"));
        syscalls.put(3, new SyscallInfo("read", 3, 
                        new String[]{"int", "void*", "size_t"}, "ssize_t", 
                        "Read from a file descriptor"));
        syscalls.put(4, new SyscallInfo("write", 3, 
                        new String[]{"int", "const void*", "size_t"}, "ssize_t", 
                        "Write to a file descriptor"));
        syscalls.put(5, new SyscallInfo("open", 3, 
                        new String[]{"const char*", "int", "mode_t"}, "int", 
                        "Open a file or device"));
        syscalls.put(6, new SyscallInfo("close", 1, 
                        new String[]{"int"}, "int", "Close a file descriptor"));
        syscalls.put(11, new SyscallInfo("execve", 3, 
                        new String[]{"const char*", "char* const[]", "char* const[]"}, "int", 
                        "Execute program"));
        syscalls.put(20, new SyscallInfo("getpid", 0, 
                        new String[]{}, "pid_t", "Get process identification"));
        
        SYSCALL_MAPS.put(OS_LINUX + "_" + ArchitectureHelper.PROCESSOR_X86, syscalls);
    }
    
    /**
     * Initialize Linux x86_64 (64-bit) syscalls
     */
    private static void initLinuxX8664Syscalls() {
        Map<Integer, SyscallInfo> syscalls = new HashMap<>();
        
        // Core I/O syscalls
        syscalls.put(60, new SyscallInfo("exit", 1, 
                        new String[]{"int"}, "void", "Terminate the process"));
        syscalls.put(57, new SyscallInfo("fork", 0, 
                        new String[]{}, "pid_t", "Create a child process"));
        syscalls.put(0, new SyscallInfo("read", 3, 
                        new String[]{"int", "void*", "size_t"}, "ssize_t", 
                        "Read from a file descriptor"));
        syscalls.put(1, new SyscallInfo("write", 3, 
                        new String[]{"int", "const void*", "size_t"}, "ssize_t", 
                        "Write to a file descriptor"));
        syscalls.put(2, new SyscallInfo("open", 3, 
                        new String[]{"const char*", "int", "mode_t"}, "int", 
                        "Open a file or device"));
        syscalls.put(3, new SyscallInfo("close", 1, 
                        new String[]{"int"}, "int", "Close a file descriptor"));
        syscalls.put(59, new SyscallInfo("execve", 3, 
                        new String[]{"const char*", "char* const[]", "char* const[]"}, "int", 
                        "Execute program"));
        syscalls.put(39, new SyscallInfo("getpid", 0, 
                        new String[]{}, "pid_t", "Get process identification"));
        
        SYSCALL_MAPS.put(OS_LINUX + "_" + ArchitectureHelper.PROCESSOR_X86 + "64", syscalls);
    }
    
    /**
     * Initialize Linux ARM (32-bit) syscalls
     */
    private static void initLinuxARMSyscalls() {
        Map<Integer, SyscallInfo> syscalls = new HashMap<>();
        
        // Core I/O syscalls
        syscalls.put(1, new SyscallInfo("exit", 1, 
                        new String[]{"int"}, "void", "Terminate the process"));
        syscalls.put(2, new SyscallInfo("fork", 0, 
                        new String[]{}, "pid_t", "Create a child process"));
        syscalls.put(3, new SyscallInfo("read", 3, 
                        new String[]{"int", "void*", "size_t"}, "ssize_t", 
                        "Read from a file descriptor"));
        syscalls.put(4, new SyscallInfo("write", 3, 
                        new String[]{"int", "const void*", "size_t"}, "ssize_t", 
                        "Write to a file descriptor"));
        syscalls.put(5, new SyscallInfo("open", 3, 
                        new String[]{"const char*", "int", "mode_t"}, "int", 
                        "Open a file or device"));
        syscalls.put(6, new SyscallInfo("close", 1, 
                        new String[]{"int"}, "int", "Close a file descriptor"));
        
        SYSCALL_MAPS.put(OS_LINUX + "_" + ArchitectureHelper.PROCESSOR_ARM, syscalls);
    }
    
    /**
     * Initialize Linux ARM64 (AArch64) syscalls
     */
    private static void initLinuxARM64Syscalls() {
        Map<Integer, SyscallInfo> syscalls = new HashMap<>();
        
        // Core I/O syscalls
        syscalls.put(93, new SyscallInfo("exit", 1, 
                        new String[]{"int"}, "void", "Terminate the process"));
        syscalls.put(220, new SyscallInfo("clone", 5, 
                        new String[]{"unsigned long", "unsigned long", "int*", "int*", "unsigned long"}, "pid_t", 
                        "Create a child process"));
        syscalls.put(63, new SyscallInfo("read", 3, 
                        new String[]{"int", "void*", "size_t"}, "ssize_t", 
                        "Read from a file descriptor"));
        syscalls.put(64, new SyscallInfo("write", 3, 
                        new String[]{"int", "const void*", "size_t"}, "ssize_t", 
                        "Write to a file descriptor"));
        syscalls.put(56, new SyscallInfo("openat", 4, 
                        new String[]{"int", "const char*", "int", "mode_t"}, "int", 
                        "Open a file relative to a directory file descriptor"));
        syscalls.put(57, new SyscallInfo("close", 1, 
                        new String[]{"int"}, "int", "Close a file descriptor"));
        
        SYSCALL_MAPS.put(OS_LINUX + "_" + ArchitectureHelper.PROCESSOR_ARM + "64", syscalls);
    }
    
    /**
     * Initialize Linux MIPS syscalls
     */
    private static void initLinuxMIPSSyscalls() {
        Map<Integer, SyscallInfo> syscalls = new HashMap<>();
        
        // Core I/O syscalls
        syscalls.put(4001, new SyscallInfo("exit", 1, 
                        new String[]{"int"}, "void", "Terminate the process"));
        syscalls.put(4002, new SyscallInfo("fork", 0, 
                        new String[]{}, "pid_t", "Create a child process"));
        syscalls.put(4003, new SyscallInfo("read", 3, 
                        new String[]{"int", "void*", "size_t"}, "ssize_t", 
                        "Read from a file descriptor"));
        syscalls.put(4004, new SyscallInfo("write", 3, 
                        new String[]{"int", "const void*", "size_t"}, "ssize_t", 
                        "Write to a file descriptor"));
        syscalls.put(4005, new SyscallInfo("open", 3, 
                        new String[]{"const char*", "int", "mode_t"}, "int", 
                        "Open a file or device"));
        syscalls.put(4006, new SyscallInfo("close", 1, 
                        new String[]{"int"}, "int", "Close a file descriptor"));
        
        SYSCALL_MAPS.put(OS_LINUX + "_" + ArchitectureHelper.PROCESSOR_MIPS, syscalls);
    }
    
    /**
     * Initialize Linux PowerPC syscalls
     */
    private static void initLinuxPPCSyscalls() {
        Map<Integer, SyscallInfo> syscalls = new HashMap<>();
        
        // Core I/O syscalls
        syscalls.put(1, new SyscallInfo("exit", 1, 
                        new String[]{"int"}, "void", "Terminate the process"));
        syscalls.put(2, new SyscallInfo("fork", 0, 
                        new String[]{}, "pid_t", "Create a child process"));
        syscalls.put(3, new SyscallInfo("read", 3, 
                        new String[]{"int", "void*", "size_t"}, "ssize_t", 
                        "Read from a file descriptor"));
        syscalls.put(4, new SyscallInfo("write", 3, 
                        new String[]{"int", "const void*", "size_t"}, "ssize_t", 
                        "Write to a file descriptor"));
        syscalls.put(5, new SyscallInfo("open", 3, 
                        new String[]{"const char*", "int", "mode_t"}, "int", 
                        "Open a file or device"));
        syscalls.put(6, new SyscallInfo("close", 1, 
                        new String[]{"int"}, "int", "Close a file descriptor"));
        
        SYSCALL_MAPS.put(OS_LINUX + "_" + ArchitectureHelper.PROCESSOR_PPC, syscalls);
    }
    
    /**
     * Initialize macOS x86 (32-bit) syscalls 
     */
    private static void initMacOSX86Syscalls() {
        Map<Integer, SyscallInfo> syscalls = new HashMap<>();
        
        // Core I/O syscalls
        syscalls.put(1, new SyscallInfo("exit", 1, 
                        new String[]{"int"}, "void", "Terminate the process"));
        syscalls.put(2, new SyscallInfo("fork", 0, 
                        new String[]{}, "pid_t", "Create a child process"));
        syscalls.put(3, new SyscallInfo("read", 3, 
                        new String[]{"int", "void*", "size_t"}, "ssize_t", 
                        "Read from a file descriptor"));
        syscalls.put(4, new SyscallInfo("write", 3, 
                        new String[]{"int", "const void*", "size_t"}, "ssize_t", 
                        "Write to a file descriptor"));
        syscalls.put(5, new SyscallInfo("open", 3, 
                        new String[]{"const char*", "int", "mode_t"}, "int", 
                        "Open a file or device"));
        syscalls.put(6, new SyscallInfo("close", 1, 
                        new String[]{"int"}, "int", "Close a file descriptor"));
        
        SYSCALL_MAPS.put(OS_MACOS + "_" + ArchitectureHelper.PROCESSOR_X86, syscalls);
    }
    
    /**
     * Initialize macOS x86_64 (64-bit) syscalls
     */
    private static void initMacOSX8664Syscalls() {
        Map<Integer, SyscallInfo> syscalls = new HashMap<>();
        
        // Core I/O syscalls
        syscalls.put(1, new SyscallInfo("exit", 1, 
                        new String[]{"int"}, "void", "Terminate the process"));
        syscalls.put(2, new SyscallInfo("fork", 0, 
                        new String[]{}, "pid_t", "Create a child process"));
        syscalls.put(3, new SyscallInfo("read", 3, 
                        new String[]{"int", "void*", "size_t"}, "ssize_t", 
                        "Read from a file descriptor"));
        syscalls.put(4, new SyscallInfo("write", 3, 
                        new String[]{"int", "const void*", "size_t"}, "ssize_t", 
                        "Write to a file descriptor"));
        syscalls.put(5, new SyscallInfo("open", 3, 
                        new String[]{"const char*", "int", "mode_t"}, "int", 
                        "Open a file or device"));
        syscalls.put(6, new SyscallInfo("close", 1, 
                        new String[]{"int"}, "int", "Close a file descriptor"));
        
        SYSCALL_MAPS.put(OS_MACOS + "_" + ArchitectureHelper.PROCESSOR_X86 + "64", syscalls);
    }
    
    /**
     * Initialize macOS ARM (Apple Silicon) syscalls
     */
    private static void initMacOSARMSyscalls() {
        Map<Integer, SyscallInfo> syscalls = new HashMap<>();
        
        // Core I/O syscalls
        syscalls.put(1, new SyscallInfo("exit", 1, 
                        new String[]{"int"}, "void", "Terminate the process"));
        syscalls.put(2, new SyscallInfo("fork", 0, 
                        new String[]{}, "pid_t", "Create a child process"));
        syscalls.put(3, new SyscallInfo("read", 3, 
                        new String[]{"int", "void*", "size_t"}, "ssize_t", 
                        "Read from a file descriptor"));
        syscalls.put(4, new SyscallInfo("write", 3, 
                        new String[]{"int", "const void*", "size_t"}, "ssize_t", 
                        "Write to a file descriptor"));
        syscalls.put(5, new SyscallInfo("open", 3, 
                        new String[]{"const char*", "int", "mode_t"}, "int", 
                        "Open a file or device"));
        syscalls.put(6, new SyscallInfo("close", 1, 
                        new String[]{"int"}, "int", "Close a file descriptor"));
        
        SYSCALL_MAPS.put(OS_MACOS + "_" + ArchitectureHelper.PROCESSOR_ARM, syscalls);
    }
    
    /**
     * Initialize Windows x86 (32-bit) syscalls/API
     * Windows uses a different syscall model via int 2Eh or sysenter
     */
    private static void initWindowsX86Syscalls() {
        Map<Integer, SyscallInfo> syscalls = new HashMap<>();
        
        // Windows NT Native API calls
        syscalls.put(0x3, new SyscallInfo("NtClose", 1, 
                        new String[]{"HANDLE"}, "NTSTATUS", "Closes an object handle"));
        syscalls.put(0x17, new SyscallInfo("NtCreateFile", 11, 
                        new String[]{"PHANDLE", "ACCESS_MASK", "POBJECT_ATTRIBUTES", "PIO_STATUS_BLOCK", 
                                   "PLARGE_INTEGER", "ULONG", "ULONG", "ULONG", "ULONG", "PVOID", "ULONG"}, 
                        "NTSTATUS", "Creates or opens a file"));
        syscalls.put(0x112, new SyscallInfo("NtReadFile", 9, 
                        new String[]{"HANDLE", "HANDLE", "PIO_APC_ROUTINE", "PVOID", "PIO_STATUS_BLOCK", 
                                   "PVOID", "ULONG", "PLARGE_INTEGER", "PULONG"}, 
                        "NTSTATUS", "Reads from a file"));
        syscalls.put(0x182, new SyscallInfo("NtWriteFile", 9, 
                        new String[]{"HANDLE", "HANDLE", "PIO_APC_ROUTINE", "PVOID", "PIO_STATUS_BLOCK", 
                                   "PVOID", "ULONG", "PLARGE_INTEGER", "PULONG"}, 
                        "NTSTATUS", "Writes to a file"));
        
        SYSCALL_MAPS.put(OS_WINDOWS + "_" + ArchitectureHelper.PROCESSOR_X86, syscalls);
    }
    
    /**
     * Initialize Windows x86_64 (64-bit) syscalls/API
     */
    private static void initWindowsX8664Syscalls() {
        Map<Integer, SyscallInfo> syscalls = new HashMap<>();
        
        // Windows NT Native API calls (x64 has different ordinals)
        syscalls.put(0xC, new SyscallInfo("NtClose", 1, 
                        new String[]{"HANDLE"}, "NTSTATUS", "Closes an object handle"));
        syscalls.put(0x55, new SyscallInfo("NtCreateFile", 11, 
                        new String[]{"PHANDLE", "ACCESS_MASK", "POBJECT_ATTRIBUTES", "PIO_STATUS_BLOCK", 
                                   "PLARGE_INTEGER", "ULONG", "ULONG", "ULONG", "ULONG", "PVOID", "ULONG"}, 
                        "NTSTATUS", "Creates or opens a file"));
        syscalls.put(0x103, new SyscallInfo("NtReadFile", 9, 
                        new String[]{"HANDLE", "HANDLE", "PIO_APC_ROUTINE", "PVOID", "PIO_STATUS_BLOCK", 
                                   "PVOID", "ULONG", "PLARGE_INTEGER", "PULONG"}, 
                        "NTSTATUS", "Reads from a file"));
        syscalls.put(0x114, new SyscallInfo("NtWriteFile", 9, 
                        new String[]{"HANDLE", "HANDLE", "PIO_APC_ROUTINE", "PVOID", "PIO_STATUS_BLOCK", 
                                   "PVOID", "ULONG", "PLARGE_INTEGER", "PULONG"}, 
                        "NTSTATUS", "Writes to a file"));
        
        SYSCALL_MAPS.put(OS_WINDOWS + "_" + ArchitectureHelper.PROCESSOR_X86 + "64", syscalls);
    }
    
    /**
     * Attempts to determine the operating system based on the binary file.
     * Uses a combination of executable format, language ID, and other heuristics.
     * 
     * @param program The Ghidra Program object
     * @return The OS identifier (OS_LINUX, OS_MACOS, or OS_WINDOWS)
     */
    public static String determineOS(Program program) {
        if (program == null) {
            return OS_LINUX; // Default assumption
        }
        
        // Get the executable format
        String executableFormat = program.getExecutableFormat();
        
        // Check language ID for additional clues
        LanguageID languageID = program.getLanguageID();
        String languageIDString = languageID != null ? languageID.toString() : "";
        
        // Get compiler spec for additional clues
        CompilerSpec compilerSpec = program.getCompilerSpec();
        String compilerSpecID = compilerSpec != null ? compilerSpec.getCompilerSpecID().toString() : "";
        
        Msg.debug(SyscallMappings.class, "Determining OS from format: " + executableFormat + 
                 ", language: " + languageIDString + ", compiler: " + compilerSpecID);
        
        // First check executable format
        if (executableFormat != null) {
            if (executableFormat.toUpperCase().contains(FORMAT_ELF)) {
                return OS_LINUX;
            } else if (executableFormat.toUpperCase().contains(FORMAT_PE) || 
                      executableFormat.toUpperCase().contains("COFF")) {
                return OS_WINDOWS;
            } else if (executableFormat.toUpperCase().contains(FORMAT_MACHO) || 
                      executableFormat.toUpperCase().contains("MACHO")) {
                return OS_MACOS;
            }
        }
        
        // Use language ID as a fallback
        if (languageIDString.contains("windows")) {
            return OS_WINDOWS;
        } else if (languageIDString.contains("mac")) {
            return OS_MACOS;
        }
        
        // Use compiler spec as a secondary fallback
        if (compilerSpecID.contains("windows")) {
            return OS_WINDOWS;
        } else if (compilerSpecID.contains("mac")) {
            return OS_MACOS;
        }
        
        // Default fallback
        return OS_LINUX;
    }
    
    /**
     * Get information about a syscall for a specific OS and processor.
     * 
     * @param os The operating system (e.g., "linux", "macOS")
     * @param processor The processor architecture (e.g., "x86", "ARM")
     * @param syscallNum The syscall number
     * @return The syscall information, or null if not found
     */
    public static SyscallInfo getSyscallInfo(String os, String processor, int syscallNum) {
        String key = os + "_" + processor;
        Map<Integer, SyscallInfo> syscallMap = SYSCALL_MAPS.get(key);
        
        if (syscallMap != null) {
            return syscallMap.get(syscallNum);
        }
        
        return null;
    }
    
    /**
     * Get the name of a syscall for a specific OS and processor.
     * 
     * @param os The operating system (e.g., "linux", "macOS")
     * @param processor The processor architecture (e.g., "x86", "ARM")
     * @param syscallNum The syscall number
     * @return The syscall name, or null if not found
     */
    public static String getSyscallName(String os, String processor, int syscallNum) {
        SyscallInfo info = getSyscallInfo(os, processor, syscallNum);
        return info != null ? info.name() : null;
    }
    
    /**
     * Get syscall parameter count for a specific OS, processor, and syscall number.
     * 
     * @param os The operating system (e.g., "linux", "macOS")
     * @param processor The processor architecture (e.g., "x86", "ARM")
     * @param syscallNum The syscall number
     * @return The parameter count, or -1 if syscall not found
     */
    public static int getSyscallParamCount(String os, String processor, int syscallNum) {
        SyscallInfo info = getSyscallInfo(os, processor, syscallNum);
        return info != null ? info.paramCount() : -1;
    }
    
    /**
     * Get all syscall information for a specific OS and processor.
     * 
     * @param os The operating system
     * @param processor The processor architecture
     * @return Map of syscall numbers to syscall information
     */
    public static Map<Integer, SyscallInfo> getAllSyscalls(String os, String processor) {
        String key = os + "_" + processor;
        Map<Integer, SyscallInfo> syscallMap = SYSCALL_MAPS.get(key);
        
        if (syscallMap != null) {
            return new HashMap<>(syscallMap); // Return a copy for safety
        }
        
        return new HashMap<>(); // Empty map if not found
    }
    
    /**
     * Determines if a syscall is related to I/O operations.
     * 
     * @param os The operating system
     * @param processor The processor architecture
     * @param syscallNum The syscall number
     * @return true if the syscall is I/O related, false otherwise or if not found
     */
    public static boolean isIOSyscall(String os, String processor, int syscallNum) {
        SyscallInfo info = getSyscallInfo(os, processor, syscallNum);
        if (info == null) {
            return false;
        }
        
        String name = info.name().toLowerCase();
        return name.contains("read") || name.contains("write") || 
               name.contains("open") || name.contains("close") || 
               name.contains("ioctl") || name.contains("pipe") || 
               name.contains("socket") || name.contains("accept") || 
               name.contains("file");
    }
    
    /**
     * Check if the operating system is supported for syscall mapping.
     * 
     * @param os The operating system to check
     * @return true if the OS is supported, false otherwise
     */
    public static boolean isOSSupported(String os) {
        return OS_LINUX.equals(os) || OS_MACOS.equals(os) || OS_WINDOWS.equals(os);
    }
    
    /**
     * Check if a specific OS/processor combination is supported for syscall mapping.
     * 
     * @param os The operating system
     * @param processor The processor architecture
     * @return true if the combination is supported, false otherwise
     */
    public static boolean isSupported(String os, String processor) {
        String key = os + "_" + processor;
        return SYSCALL_MAPS.containsKey(key);
    }
}
