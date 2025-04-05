package com.juliandavis.ghidramcp.services;

import com.juliandavis.ghidramcp.core.service.Service;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.util.Msg;

import javax.swing.SwingUtilities;
import java.lang.reflect.InvocationTargetException;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Service for disassembling code and managing assembly-level operations in Ghidra.
 */
public class DisassembleService implements Service {

    public static final String SERVICE_NAME = "DisassembleService";
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
     * Initialize the service with the current program.
     *
     * @param program the current Ghidra program
     */
    @Override
    public void initialize(Program program) {
        this.program = program;
    }

    /**
     * Dispose of service resources
     */
    @Override
    public void dispose() {
        // No resources to dispose
        this.program = null;
    }

    /**
     * Get disassembly at a specific address for a given number of instructions
     *
     * @param addressStr The address to disassemble from (as a string)
     * @param instructionCount The number of instructions to disassemble
     * @return Map containing the disassembly results
     */
    public Map<String, Object> getDisassemblyAtAddress(String addressStr, int instructionCount) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return createErrorResponse("Address is required");
        }

        if (instructionCount <= 0) {
            return createErrorResponse("Instruction count must be positive");
        }

        try {
            Address address = program.getAddressFactory().getAddress(addressStr);
            if (address == null) {
                return createErrorResponse("Invalid address: " + addressStr);
            }

            // Determine the containing function (if any)
            Function function = program.getFunctionManager().getFunctionContaining(address);

            // Get all instructions starting from the given address
            List<Map<String, Object>> instructions = new ArrayList<>();
            Listing listing = program.getListing();
            int count = 0;

            Address currentAddress = address;
            while (count < instructionCount) {
                if (currentAddress == null || !program.getMemory().contains(currentAddress)) {
                    break;
                }

                Instruction instr = listing.getInstructionAt(currentAddress);
                if (instr == null) {
                    break;
                }

                Map<String, Object> instrData = createInstructionData(instr, function);
                instructions.add(instrData);

                try {
                    currentAddress = instr.getAddress().add(instr.getLength());
                } catch (Exception e) {
                    break;
                }
                count++;
            }

            Map<String, Object> result = new HashMap<>();
            result.put("address", address.toString());
            result.put("instructions", instructions);
            result.put("count", instructions.size());
            if (function != null) {
                result.put("function", function.getName());
            }
            result.put("success", true);

            return createSuccessResponse(result);

        } catch (Exception e) {
            Msg.error(this, "Error getting disassembly for address " + addressStr, e);
            return createErrorResponse("Invalid address or error: " + e.getMessage());
        }
    }

    /**
     * Get disassembly listing for a specific function by name
     *
     * @param name The name of the function to disassemble
     * @return Map containing the disassembly results
     */
    public Map<String, Object> getDisassemblyForFunction(String name) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (name == null || name.isEmpty()) {
            return createErrorResponse("Function name is required");
        }

        try {
            // Find the function by name
            Function function = null;
            for (Function func : program.getFunctionManager().getFunctions(true)) {
                if (func.getName().equals(name)) {
                    function = func;
                    break;
                }
            }

            if (function == null) {
                return createErrorResponse("Function not found: " + name);
            }

            // Get function boundaries
            Address start = function.getEntryPoint();
            Address end = function.getBody().getMaxAddress();

            // Use the address range to get disassembly
            Map<String, Object> result = getDisassemblyInRange(start, end, function);
            return createSuccessResponse(result);

        } catch (Exception e) {
            Msg.error(this, "Error getting disassembly for function " + name, e);
            return createErrorResponse("Error: " + e.getMessage());
        }
    }

    /**
     * Set a comment at the specified address
     * 
     * @param addressStr The address where to set the comment
     * @param comment The comment text
     * @param commentType The type of comment (see CodeUnit.XXX_COMMENT constants)
     * @return Map containing the result of the operation
     */
    public Map<String, Object> setCommentAtAddress(String addressStr, String comment, int commentType) {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return createErrorResponse("Address is required");
        }

        // Validate comment type
        if (commentType != CodeUnit.PLATE_COMMENT &&
                commentType != CodeUnit.PRE_COMMENT &&
                commentType != CodeUnit.EOL_COMMENT &&
                commentType != CodeUnit.POST_COMMENT &&
                commentType != CodeUnit.REPEATABLE_COMMENT) {

            return createErrorResponse("Invalid comment type: " + commentType);
        }

        AtomicBoolean successFlag = new AtomicBoolean(false);

        try {
            SwingUtilities.invokeAndWait(() -> {
                int tx = program.startTransaction("Set comment");
                try {
                    Address address = program.getAddressFactory().getAddress(addressStr);
                    if (address == null) {
                        throw new IllegalArgumentException("Invalid address: " + addressStr);
                    }

                    // Get the code unit at this address (could be an instruction or data)
                    CodeUnit codeUnit = program.getListing().getCodeUnitAt(address);
                    if (codeUnit != null) {
                        codeUnit.setComment(commentType, comment);
                        successFlag.set(true);
                    } else {
                        Msg.warn(this, "No code unit found at address: " + addressStr);
                    }
                }
                catch (Exception e) {
                    Msg.error(this, "Error setting comment at address " + addressStr, e);
                }
                finally {
                    program.endTransaction(tx, true);
                }
            });
        }
        catch (InterruptedException | InvocationTargetException e) {
            Msg.error(this, "Failed to execute set comment on Swing thread", e);
            return createErrorResponse("Error: " + e.getMessage());
        }

        Map<String, Object> result = new HashMap<>();
        result.put("success", successFlag.get());
        result.put("address", addressStr);
        result.put("commentType", commentType);

        // If we know comment type names, include them
        String commentTypeName = switch (commentType) {
            case CodeUnit.PLATE_COMMENT -> "PLATE";
            case CodeUnit.PRE_COMMENT -> "PRE";
            case CodeUnit.EOL_COMMENT -> "EOL";
            case CodeUnit.POST_COMMENT -> "POST";
            case CodeUnit.REPEATABLE_COMMENT -> "REPEATABLE";
            default -> "UNKNOWN";
        };
        result.put("commentTypeName", commentTypeName);

        if (!successFlag.get()) {
            result.put("message", "Failed to set comment - no code unit at address");
        }

        return createSuccessResponse(result);
    }

    /**
     * Get disassembly for an address range (internal helper method)
     */
    private Map<String, Object> getDisassemblyInRange(Address start, Address end, Function function) throws MemoryAccessException {
        if (program == null) {
            return createErrorResponse("No program loaded");
        }

        Listing listing = program.getListing();
        List<Map<String, Object>> instructions = new ArrayList<>();

        Address currentAddress = start;
        while (currentAddress != null && currentAddress.compareTo(end) <= 0) {
            if (!program.getMemory().contains(currentAddress)) {
                // Skip to next address
                currentAddress = currentAddress.add(1);
                continue;
            }

            Instruction instr = listing.getInstructionAt(currentAddress);
            if (instr == null) {
                currentAddress = currentAddress.add(1);
                continue;
            }

            Map<String, Object> instrData = createInstructionData(instr, function);
            instructions.add(instrData);

            // Go to the next instruction
            try {
                currentAddress = instr.getAddress().add(instr.getLength());
            } catch (Exception e) {
                currentAddress = currentAddress.add(1);
            }
        }

        Map<String, Object> result = new HashMap<>();
        assert start != null;
        result.put("start", start.toString());
        result.put("end", end.toString());
        result.put("instructions", instructions);
        result.put("count", instructions.size());
        if (function != null) {
            result.put("function", function.getName());
            result.put("signature", function.getSignature().toString());
        }
        result.put("success", true);

        return result;
    }

    /**
     * Create a map of instruction data (internal helper)
     */
    private Map<String, Object> createInstructionData(Instruction instr, Function function) throws MemoryAccessException {
        Map<String, Object> instrData = new HashMap<>();
        instrData.put("address", instr.getAddress().toString());
        instrData.put("bytes", bytesToHexString(instr.getParsedBytes()));
        instrData.put("mnemonic", instr.getMnemonicString());

        // Get the full representation with operands
        String representation = instr.toString();
        instrData.put("representation", representation);

        // Extract operands info
        List<Map<String, Object>> operands = new ArrayList<>();
        for (int i = 0; i < instr.getNumOperands(); i++) {
            Map<String, Object> operandData = new HashMap<>();
            operandData.put("index", i);
            operandData.put("text", instr.getDefaultOperandRepresentation(i));
            operandData.put("type", instr.getOperandType(i));

            // For references, include the target information
            instr.getOperandType(i);

            // Check if this operand has any references
            Reference[] refs = instr.getOperandReferences(i);
            if (refs != null && refs.length > 0) {

                List<Map<String, Object>> refList = new ArrayList<>();

                for (Reference ref : refs) {
                    Map<String, Object> refData = new HashMap<>();
                    refData.put("toAddress", ref.getToAddress().toString());
                    refData.put("type", ref.getReferenceType().toString());

                    // Add target information if it's a function
                    Function targetFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                    if (targetFunc != null) {
                        refData.put("toFunction", targetFunc.getName());
                    }

                    refList.add(refData);
                }

                operandData.put("references", refList);
            }

            operands.add(operandData);
        }
        instrData.put("operands", operands);

        // Add any comments
        String comment = program.getListing().getComment(
                CodeUnit.PLATE_COMMENT, instr.getAddress());
        if (comment != null && !comment.isEmpty()) {
            instrData.put("plateComment", comment);
        }

        comment = program.getListing().getComment(
                CodeUnit.PRE_COMMENT, instr.getAddress());
        if (comment != null && !comment.isEmpty()) {
            instrData.put("preComment", comment);
        }

        comment = program.getListing().getComment(
                CodeUnit.EOL_COMMENT, instr.getAddress());
        if (comment != null && !comment.isEmpty()) {
            instrData.put("eolComment", comment);
        }

        comment = program.getListing().getComment(
                CodeUnit.POST_COMMENT, instr.getAddress());
        if (comment != null && !comment.isEmpty()) {
            instrData.put("postComment", comment);
        }

        // If this instruction is the entry point of a function, mark it
        Function funcAtAddr = program.getFunctionManager().getFunctionAt(instr.getAddress());
        if (funcAtAddr != null) {
            instrData.put("isEntryPoint", true);
            instrData.put("functionName", funcAtAddr.getName());
        }

        // Determine relative position in the containing function
        if (function != null) {
            long offset = instr.getAddress().subtract(function.getEntryPoint());
            instrData.put("functionOffset", offset);
        }

        return instrData;
    }

    /**
     * Convert byte array to hex string (internal helper)
     */
    private String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Creates a standardized error response with default error code (400)
     *
     * @param errorMessage The error message
     * @return Map representing the error response
     */
    private Map<String, Object> createErrorResponse(String errorMessage) {
        return createErrorResponse(errorMessage, 400);
    }

    /**
     * Creates a standardized error response
     *
     * @param errorMessage The error message
     * @param errorCode Optional error code
     * @return Map representing the error response
     */
    private Map<String, Object> createErrorResponse(String errorMessage, int errorCode) {
        Map<String, Object> response = new HashMap<>();
        Map<String, Object> errorDetails = new HashMap<>();

        // Standard top-level structure
        response.put("status", "error");

        // Error details
        errorDetails.put("message", errorMessage);
        errorDetails.put("code", errorCode);

        response.put("error", errorDetails);

        return response;
    }

    /**
     * Creates a standardized success response
     *
     * @param data The data to include in the response
     * @return Map representing the success response
     */
    private Map<String, Object> createSuccessResponse(Map<String, Object> data) {
        Map<String, Object> response = new HashMap<>();

        // Standard top-level structure
        response.put("status", "success");
        response.put("data", data);

        return response;
    }
}
