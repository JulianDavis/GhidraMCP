"""
Rich result objects for GhidraMCP.

These objects provide structured representations of the responses from the 
Ghidra Model Context Protocol server. They have proper typing and documentation,
making them easier to work with in IDEs and code editors.
"""

from typing import Dict, List, Optional, Any, Union, TypeVar, Generic
from dataclasses import dataclass

T = TypeVar('T')

@dataclass
class BaseResult(Generic[T]):
    """Base class for all result objects."""
    success: bool
    status: str  # 'success' or 'error'
    data: Optional[T] = None
    error: Optional[Dict[str, Any]] = None
    
    @classmethod
    def from_dict(cls, response: Dict[str, Any]) -> 'BaseResult':
        """Create a BaseResult object from a response dictionary."""
        # Check if the response is already a BaseResult
        if isinstance(response, cls):
            return response
            
        # Check for standardized response format
        if "status" in response:
            is_success = response.get("status") == "success"
            
            return cls(
                success=is_success,
                status=response.get("status", ""),
                data=response.get("data") if is_success else None,
                error=response.get("error") if not is_success else None
            )
        
        # Fall back to old format with direct "success" field
        is_success = response.get("success", False)
        
        return cls(
            success=is_success,
            status="success" if is_success else "error",
            data=response if is_success else None,
            error={"message": response.get("error", "Unknown error")} if not is_success else None
        )

@dataclass
class EmulatorState:
    """Represents the current state of the emulator."""
    registers: Dict[str, str]
    programCounter: str
    memory: Dict[str, Any]
    status: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EmulatorState':
        """Create an EmulatorState object from a dictionary."""
        return cls(
            registers=data.get('registers', {}),
            programCounter=data.get('programCounter', ''),
            memory=data.get('memory', {}),
            status=data.get('status', '')
        )

@dataclass
class MemoryAccess:
    """Represents a memory read or write operation."""
    address: str
    length: int
    hexValue: str
    asciiValue: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MemoryAccess':
        """Create a MemoryAccess object from a dictionary."""
        return cls(
            address=data.get('address', ''),
            length=data.get('length', 0),
            hexValue=data.get('hexValue', ''),
            asciiValue=data.get('asciiValue', '')
        )

@dataclass
class Breakpoint:
    """Represents a breakpoint in the emulator."""
    address: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Breakpoint':
        """Create a Breakpoint object from a dictionary."""
        return cls(
            address=data.get('address', '')
        )

@dataclass
class ConditionalBreakpoint:
    """Represents a conditional breakpoint in the emulator."""
    address: str
    condition: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConditionalBreakpoint':
        """Create a ConditionalBreakpoint object from a dictionary."""
        return cls(
            address=data.get('address', ''),
            condition=data.get('condition', '')
        )

@dataclass
class RegisterValue:
    """Represents a register and its value."""
    register: str
    value: str
    decimal: int
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RegisterValue':
        """Create a RegisterValue object from a dictionary."""
        return cls(
            register=data.get('register', ''),
            value=data.get('value', ''),
            decimal=data.get('decimal', 0)
        )

@dataclass
class StepResult:
    """Represents the result of stepping the emulator."""
    previousPC: str
    newPC: str
    instruction: Optional[str] = None
    sessionId: Optional[str] = None
    fromAddress: Optional[str] = None
    toAddress: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StepResult':
        """Create a StepResult object from a dictionary."""
        # Check for the new standardized format with nested data
        if "status" in data and data.get("status") == "success" and "data" in data:
            step_data = data.get("data", {})
            return cls(
                previousPC=step_data.get('fromAddress', ''),
                newPC=step_data.get('toAddress', ''),
                instruction=step_data.get('instruction'),
                sessionId=step_data.get('sessionId'),
                fromAddress=step_data.get('fromAddress'),
                toAddress=step_data.get('toAddress')
            )
            
        # Fall back to the old format
        return cls(
            previousPC=data.get('previousPC', ''),
            newPC=data.get('newPC', ''),
            instruction=data.get('instruction')
        )

@dataclass
class RunResult:
    """Represents the result of running the emulator."""
    stepsExecuted: int
    currentPC: str
    stoppedReason: Optional[str] = None
    executedInstructions: List[str] = None
    sessionId: Optional[str] = None
    fromAddress: Optional[str] = None
    toAddress: Optional[str] = None
    hitBreakpoint: Optional[bool] = None
    reachedStopAddress: Optional[bool] = None
    hitMaxSteps: Optional[bool] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RunResult':
        """Create a RunResult object from a dictionary."""
        # Check for the new standardized format with nested data
        if "status" in data and data.get("status") == "success" and "data" in data:
            run_data = data.get("data", {})
            if not run_data:  # Empty data
                return cls(stepsExecuted=0, currentPC="")
                
            # When the currentPC field is not present, use toAddress instead
            current_pc = run_data.get('currentPC', run_data.get('toAddress', ''))
            
            return cls(
                stepsExecuted=run_data.get('stepsExecuted', 0),
                currentPC=current_pc,
                stoppedReason=run_data.get('stoppedReason'),
                executedInstructions=run_data.get('executedInstructions', []),
                sessionId=run_data.get('sessionId'),
                fromAddress=run_data.get('fromAddress'),
                toAddress=run_data.get('toAddress'),
                hitBreakpoint=run_data.get('hitBreakpoint'),
                reachedStopAddress=run_data.get('reachedStopAddress'),
                hitMaxSteps=run_data.get('hitMaxSteps')
            )
            
        # Fall back to the old format
        return cls(
            stepsExecuted=data.get('stepsExecuted', 0),
            currentPC=data.get('currentPC', ''),
            stoppedReason=data.get('stoppedReason', ''),
            executedInstructions=data.get('executedInstructions', [])
        )

@dataclass
class MemoryWriteResult:
    """Represents the result of writing to memory."""
    address: str
    bytesWritten: int
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MemoryWriteResult':
        """Create a MemoryWriteResult object from a dictionary."""
        return cls(
            address=data.get('address', ''),
            bytesWritten=data.get('bytesWritten', 0)
        )

@dataclass
class Instruction:
    """Represents a disassembled instruction."""
    address: str
    bytes: str
    mnemonic: str
    representation: str
    operands: List[str]
    comments: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Instruction':
        """Create an Instruction object from a dictionary."""
        return cls(
            address=data.get('address', ''),
            bytes=data.get('bytes', ''),
            mnemonic=data.get('mnemonic', ''),
            representation=data.get('representation', ''),
            operands=data.get('operands', []),
            comments=data.get('comments')
        )

@dataclass
class DisassemblyResult:
    """Represents the result of disassembling code."""
    address: str
    instructions: List[Instruction]
    count: int
    function: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DisassemblyResult':
        """Create a DisassemblyResult object from a dictionary."""
        # Check for the new standardized format with nested data
        if "status" in data and data.get("status") == "success" and "data" in data:
            disasm_data = data.get("data", {})
            return cls(
                address=disasm_data.get('address', ''),
                instructions=[Instruction.from_dict(instr) for instr in disasm_data.get('instructions', [])],
                count=disasm_data.get('count', 0),
                function=disasm_data.get('function')
            )
            
        # Fall back to the old format
        return cls(
            address=data.get('address', ''),
            instructions=[Instruction.from_dict(instr) for instr in data.get('instructions', [])],
            count=data.get('count', 0),
            function=data.get('function')
        )

@dataclass
class FunctionDisassemblyResult:
    """Represents the result of disassembling a function."""
    start: str
    end: str
    instructions: List[Instruction]
    count: int
    function: str
    signature: str
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FunctionDisassemblyResult':
        """Create a FunctionDisassemblyResult object from a dictionary."""
        # Check for the new standardized format with nested data
        if "status" in data and data.get("status") == "success" and "data" in data:
            disasm_data = data.get("data", {})
            return cls(
                start=disasm_data.get('start', ''),
                end=disasm_data.get('end', ''),
                instructions=[Instruction.from_dict(instr) for instr in disasm_data.get('instructions', [])],
                count=disasm_data.get('count', 0),
                function=disasm_data.get('function', ''),
                signature=disasm_data.get('signature', '')
            )
            
        # Fall back to the old format
        return cls(
            start=data.get('start', ''),
            end=data.get('end', ''),
            instructions=[Instruction.from_dict(instr) for instr in data.get('instructions', [])],
            count=data.get('count', 0),
            function=data.get('function', ''),
            signature=data.get('signature', '')
        )

@dataclass
class Reference:
    """Represents a cross-reference."""
    fromAddress: str
    toAddress: str
    referenceType: str
    function: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Reference':
        """Create a Reference object from a dictionary."""
        return cls(
            fromAddress=data.get('fromAddress', ''),
            toAddress=data.get('toAddress', ''),
            referenceType=data.get('referenceType', ''),
            function=data.get('function')
        )

@dataclass
class ReferenceResult:
    """Represents the result of getting references to/from an address."""
    address: str
    referencesToHere: List[Reference]
    referencesFromHere: List[Reference]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ReferenceResult':
        """Create a ReferenceResult object from a dictionary."""
        # Check for the new standardized format with nested data
        if "status" in data and data.get("status") == "success" and "data" in data:
            ref_data = data.get("data", {})
            return cls(
                address=ref_data.get('address', ''),
                referencesToHere=[Reference.from_dict(ref) for ref in ref_data.get('referencesToHere', [])],
                referencesFromHere=[Reference.from_dict(ref) for ref in ref_data.get('referencesFromHere', [])]
            )
            
        # Fall back to the old format
        return cls(
            address=data.get('address', ''),
            referencesToHere=[Reference.from_dict(ref) for ref in data.get('referencesToHere', [])],
            referencesFromHere=[Reference.from_dict(ref) for ref in data.get('referencesFromHere', [])]
        )

@dataclass
class MemoryReadsResult:
    """Represents the result of getting memory reads."""
    reads: List[MemoryAccess]
    count: int
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MemoryReadsResult':
        """Create a MemoryReadsResult object from a dictionary."""
        return cls(
            reads=[MemoryAccess.from_dict(read) for read in data.get('reads', [])],
            count=data.get('count', 0)
        )

@dataclass
class MemoryWritesResult:
    """Represents the result of getting memory writes."""
    writes: List[MemoryAccess]
    count: int
    totalBytes: Optional[int] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MemoryWritesResult':
        """Create a MemoryWritesResult object from a dictionary."""
        # Check for the new standardized format with nested data
        if "status" in data and data.get("status") == "success" and "data" in data:
            writes_data = data.get("data", {})
            return cls(
                writes=[MemoryAccess.from_dict(write) for write in writes_data.get('writes', [])],
                count=writes_data.get('count', 0),
                totalBytes=writes_data.get('totalBytes')
            )
            
        # Fall back to the old format
        return cls(
            writes=[MemoryAccess.from_dict(write) for write in data.get('writes', [])],
            count=data.get('count', 0)
        )

@dataclass
class BreakpointsResult:
    """Represents the result of getting breakpoints."""
    breakpoints: List[str]
    count: int
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BreakpointsResult':
        """Create a BreakpointsResult object from a dictionary."""
        # Check for the new standardized format with nested data
        if "status" in data and data.get("status") == "success" and "data" in data:
            bp_data = data.get("data", {})
            return cls(
                breakpoints=bp_data.get('breakpoints', []),
                count=bp_data.get('count', 0)
            )
            
        # Fall back to the old format
        return cls(
            breakpoints=data.get('breakpoints', []),
            count=data.get('count', 0)
        )

@dataclass
class ConditionalBreakpointsResult:
    """Represents the result of getting conditional breakpoints."""
    breakpoints: List[ConditionalBreakpoint]
    count: int
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ConditionalBreakpointsResult':
        """Create a ConditionalBreakpointsResult object from a dictionary."""
        # Check for the new standardized format with nested data
        if "status" in data and data.get("status") == "success" and "data" in data:
            bp_data = data.get("data", {})
            return cls(
                breakpoints=[ConditionalBreakpoint.from_dict(bp) for bp in bp_data.get('breakpoints', [])],
                count=bp_data.get('count', 0)
            )
            
        # Fall back to the old format
        return cls(
            breakpoints=[ConditionalBreakpoint.from_dict(bp) for bp in data.get('breakpoints', [])],
            count=data.get('count', 0)
        )

@dataclass
class FunctionInfo:
    """Represents information about a function."""
    name: str
    address: str
    signature: Optional[str] = None
    entryPoint: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FunctionInfo':
        """Create a FunctionInfo object from a dictionary."""
        return cls(
            name=data.get('name', ''),
            address=data.get('address', ''),
            signature=data.get('signature'),
            entryPoint=data.get('entryPoint')
        )

@dataclass
class StackTraceResult:
    """Represents the result of getting a stack trace."""
    stackTrace: List[Dict[str, Any]]
    count: int
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StackTraceResult':
        """Create a StackTraceResult object from a dictionary."""
        return cls(
            stackTrace=data.get('stackTrace', []),
            count=data.get('count', 0)
        )

@dataclass
class EmulatorSession:
    """Represents an emulator session."""
    sessionId: str
    status: str
    programCounter: Optional[str] = None
    writeTracking: Optional[bool] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EmulatorSession':
        """Create an EmulatorSession object from a dictionary."""
        # Check for the new standardized format with nested data
        if "status" in data and data.get("status") == "success" and "data" in data:
            session_data = data.get("data", {})
            return cls(
                sessionId=session_data.get('sessionId', ''),
                status=session_data.get('status', 'initialized'),
                programCounter=session_data.get('programCounter'),
                writeTracking=session_data.get('writeTracking')
            )
            
        # Fall back to the old format
        return cls(
            sessionId=data.get('sessionId', ''),
            status=data.get('status', '')
        )

@dataclass
class ErrorResult:
    """Represents an error result."""
    success: bool = False
    error: Optional[str] = None
    error_code: Optional[int] = None
    status: str = "error"
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ErrorResult':
        """Create an ErrorResult object from a dictionary."""
        # Handle new standardized error format
        if "status" in data and data.get("status") == "error" and "error" in data:
            error_data = data.get("error", {})
            if isinstance(error_data, dict):
                return cls(
                    success=False,
                    error=error_data.get("message"),
                    error_code=error_data.get("code", 400),
                    status="error"
                )
            
        # Fall back to old format
        return cls(
            success=data.get('success', False),
            error=data.get('error'),
            status="error"
        )
    
    @classmethod
    def from_string(cls, error_str: str) -> 'ErrorResult':
        """Create an ErrorResult object from an error string."""
        return cls(
            success=False,
            error=error_str,
            status="error"
        )
