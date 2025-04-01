package com.juliandavis.ghidramcp.services.emulator.operations;

import com.juliandavis.ghidramcp.services.emulator.session.EmulatorSession;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

import java.math.BigInteger;

/**
 * Utility class for evaluating breakpoint conditions during emulation.
 */
public class BreakpointEvaluator {

    /**
     * Evaluates a conditional breakpoint expression
     * 
     * @param session The emulator session
     * @param condition The condition expression to evaluate
     * @return true if the condition is met, false otherwise
     */
    public static boolean evaluateBreakpointCondition(EmulatorSession session, String condition) {
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
                            Msg.warn(BreakpointEvaluator.class, "Cannot read memory at " + addr + ": " + e.getMessage());
                        }
                    }
                }
            }
            
            // Could add more condition types here if needed
            
            return false;
        } catch (Exception e) {
            Msg.error(BreakpointEvaluator.class, "Error evaluating breakpoint condition: " + condition, e);
            return false;
        }
    }
}