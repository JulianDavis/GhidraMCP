"""
Rich result objects for GhidraMCP.

These objects provide structured representations of the responses from the 
Ghidra Model Context Protocol server. They have proper typing and documentation,
making them easier to work with in IDEs and code editors.
"""

from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass

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
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'StepResult':
        """Create a StepResult object from a dictionary."""
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
    stoppedReason: str
    executedInstructions: List[str]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'RunResult':
        """Create a RunResult object from a dictionary."""
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
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MemoryWritesResult':
        """Create a MemoryWritesResult object from a dictionary."""
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
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EmulatorSession':
        """Create an EmulatorSession object from a dictionary."""
        return cls(
            sessionId=data.get('sessionId', ''),
            status=data.get('status', '')
        )

@dataclass
class ErrorResult:
    """Represents an error result."""
    success: bool = False
    error: Optional[str] = None
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ErrorResult':
        """Create an ErrorResult object from a dictionary."""
        return cls(
            success=data.get('success', False),
            error=data.get('error')
        )
    
    @classmethod
    def from_string(cls, error_str: str) -> 'ErrorResult':
        """Create an ErrorResult object from an error string."""
        return cls(
            success=False,
            error=error_str
        )
