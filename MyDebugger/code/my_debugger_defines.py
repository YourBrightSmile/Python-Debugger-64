# -*- coding: utf-8 -*- 
from ctypes import *

'''
    存放所有结构体，联合体，常值定义

'''

# 给ctype变量赋别名，可以使代码更接近win32风格
WORD    = c_ushort  #ushort    占2个字节
DWORD   = c_ulong   #ulong     占4个字节
BYTE    = c_ubyte
LPBYTE  = POINTER(c_byte)  #POINTER() 定义指针c_byte == unsigned char 
LPTSTR  = POINTER(c_char)  
HANDLE  = c_void_p  #void * 通用类型的指针
PVOID   = c_void_p

ULONG_PTR = POINTER(c_ulong)
LPVOID  = c_void_p
LPCVOID = c_void_p

UINT_PTR  = c_ulong
SIZE_T = c_ulong
DWORD64 = c_uint64

#常值
INFINITE            = 0xFFFFFFFF
CREATE_NEW_CONSOLE  = 0x00000010
PROCESS_ALL_ACCESS  = 0x001F0FFF 
DEBUG_PROCESS       = 0x00000001
#dwContinueStatus
DBG_CONTINUE                = 0x00010002
DBG_EXCEPTION_NOT_HANDLED   = 0x80010001
THREAD_ALL_ACCESS   = 0x001F03FF     #OpenThread使用dwDesireAccess
TH32CS_SNAPTHREAD   = 0x00000004     #CreateToolhelp32Snapshot dwFlags 读取所有线程信息

CONTEXT_FULL            = 0x00010007
CONTEXT_DEBUG_REGISTERS = 0x00010010

##异常dwDebugEventCode事件
EXCEPTION_DEBUG_EVENT   = 0x00000001
##ExceptionCode
EXCEPTION_ACCESS_VIOLATION  = 0xC0000005
EXCEPTION_BREAKPOINT        = 0x80000003
EXCEPTION_GUARD_PAGE        = 0x80000001 
EXCEPTION_SINGLE_STEP       = 0x80000004

##硬件断点的条件
HW_ACCESS           = 0x00000003
HW_EXECUTE          = 0x00000000
HW_WRITE            = 0x00000001

##内存页权限
PAGE_NOACCESS                  = 0x00000001
PAGE_READONLY                  = 0x00000002
PAGE_READWRITE                 = 0x00000004
PAGE_WRITECOPY                 = 0x00000008
PAGE_EXECUTE                   = 0x00000010
PAGE_EXECUTE_READ              = 0x00000020
PAGE_EXECUTE_READWRITE         = 0x00000040
PAGE_EXECUTE_WRITECOPY         = 0x00000080
PAGE_GUARD                     = 0x00000100
PAGE_NOCACHE                   = 0x00000200
PAGE_WRITECOMBINE              = 0x00000400

#定义CreateProcess所需结构体
class STARTUPINFO(Structure):
    _fields_ =[
        ("cb",          DWORD),
        ("lpReserved",  LPTSTR),
        ("lpDesktop",   LPTSTR),
        ("lpTitle",     LPTSTR),
        ("dwX",         DWORD),
        ("dwY",         DWORD),
        ("dwXSize",     DWORD),
        ("dwYSize",     DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFileAttribute",DWORD),
        ("dwFlags",     DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", WORD),
        ("hStdInput",   HANDLE),
        ("hStdOutput",  HANDLE),
        ("hStdError",   HANDLE),
    ]
    
class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
    ]

#定义DEBUG_EVENT START

class EXCEPTION_RECORD(Structure):
    pass
EXCEPTION_RECORD._fields_=[
        ("ExceptionCode",DWORD),
        ("ExceptionFlags",DWORD),
        ("ExceptionRecord",POINTER(EXCEPTION_RECORD)),##这里要使用它本身，所以在定义后再创建结构体变量
        ("ExceptionAddress",PVOID),
        ("NumberParameters",DWORD),
        ("ExceptionInformation",UINT_PTR*15)
    ]
  

 
class EXCEPTION_DEBUG_INFO(Structure):    
    _fields_ = [
        ("ExceptionRecord",EXCEPTION_RECORD),
        ("dwFirstChance",DWORD)
    ]   
class _DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception",EXCEPTION_DEBUG_INFO)
    ]    
class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode",DWORD),
        ("dwProcessId",DWORD),
        ("dwThreadId",DWORD),
        ("u",_DEBUG_EVENT_UNION)
    ]
    
#定义DEBUG_EVENT END

#THREADENTRY32
class THTREADENTRY32(Structure):
    _fields_ = [
        ("dwSize",DWORD),
        ("cntUsage",DWORD),
        ("th32ThreadID",DWORD),
        ("th32OwnerProcessID",DWORD),
        ("tpBasePri",DWORD),
        ("tpDeltaPri",DWORD),
        ("dwFlags",DWORD)
    ]




#定义64位context START
class M128A(Structure):
    _fields_ = [
            ("Low", DWORD64),
            ("High", DWORD64)
            ]
class XMM_SAVE_AREA32(Structure):
    _pack_ = 1 
    _fields_ = [  
                ('ControlWord', WORD), 
                ('StatusWord', WORD), 
                ('TagWord', BYTE), 
                ('Reserved1', BYTE), 
                ('ErrorOpcode', WORD), 
                ('ErrorOffset', DWORD), 
                ('ErrorSelector', WORD), 
                ('Reserved2', WORD), 
                ('DataOffset', DWORD), 
                ('DataSelector', WORD), 
                ('Reserved3', WORD), 
                ('MxCsr', DWORD), 
                ('MxCsr_Mask', DWORD), 
                ('FloatRegisters', M128A * 8), 
                ('XmmRegisters', M128A * 16), 
                ('Reserved4', BYTE * 96)
                ] 

  

class DUMMYSTRUCTNAME(Structure):
    _fields_=[
              ("Header", M128A * 2),
              ("Legacy", M128A * 8),
              ("Xmm0", M128A),
              ("Xmm1", M128A),
              ("Xmm2", M128A),
              ("Xmm3", M128A),
              ("Xmm4", M128A),
              ("Xmm5", M128A),
              ("Xmm6", M128A),
              ("Xmm7", M128A),
              ("Xmm8", M128A),
              ("Xmm9", M128A),
              ("Xmm10", M128A),
              ("Xmm11", M128A),
              ("Xmm12", M128A),
              ("Xmm13", M128A),
              ("Xmm14", M128A),
              ("Xmm15", M128A)
              ]
class DUMMYUNIONNAME(Union):
    _fields_=[
              ("FltSave", XMM_SAVE_AREA32),
              ("DummyStruct", DUMMYSTRUCTNAME)
              ] 

class WOW64_CONTEXT(Structure):
    _pack_ = 16
    _fields_ = [
            ("P1Home", DWORD64),
            ("P2Home", DWORD64),
            ("P3Home", DWORD64),
            ("P4Home", DWORD64),
            ("P5Home", DWORD64),
            ("P6Home", DWORD64),
 
            ("ContextFlags", DWORD),
            ("MxCsr", DWORD),
 
            ("SegCs", WORD),
            ("SegDs", WORD),
            ("SegEs", WORD),
            ("SegFs", WORD),
            ("SegGs", WORD),
            ("SegSs", WORD),
            ("EFlags", DWORD),
 
            ("Dr0", DWORD64),
            ("Dr1", DWORD64),
            ("Dr2", DWORD64),
            ("Dr3", DWORD64),
            ("Dr6", DWORD64),
            ("Dr7", DWORD64),
 
            ("Rax", DWORD64),
            ("Rcx", DWORD64),
            ("Rdx", DWORD64),
            ("Rbx", DWORD64),
            ("Rsp", DWORD64),
            ("Rbp", DWORD64),
            ("Rsi", DWORD64),
            ("Rdi", DWORD64),
            ("R8", DWORD64),
            ("R9", DWORD64),
            ("R10", DWORD64),
            ("R11", DWORD64),
            ("R12", DWORD64),
            ("R13", DWORD64),
            ("R14", DWORD64),
            ("R15", DWORD64),
            ("Rip", DWORD64),
 
            ("DebugControl", DWORD64),
            ("LastBranchToRip", DWORD64),
            ("LastBranchFromRip", DWORD64),
            ("LastExceptionToRip", DWORD64),
            ("LastExceptionFromRip", DWORD64),
 
            ("DUMMYUNIONNAME", DUMMYUNIONNAME),
 
            ("VectorRegister", M128A * 26),
            ("VectorControl", DWORD64)
]
#定义64位context END

#定义SYSTEM_INFO START
class SYSTEM_INFO(Structure):
    _fields_ = [("wProcessorArchitecture", WORD),
                ("wReserved", WORD),
                ("dwPageSize", DWORD),
                ("lpMinimumApplicationAddress", DWORD),
                ("lpMaximumApplicationAddress", DWORD),
                ("dwActiveProcessorMask", DWORD),
                ("dwNumberOfProcessors", DWORD),
                ("dwProcessorType", DWORD),
                ("dwAllocationGranularity", DWORD),
                ("wProcessorLevel", WORD),
                ("wProcessorRevision", WORD)
    ]
    
#定义SYSTEM_INFO END
    
    
#定义MEMORY_BASIC_INFORMATION START
class MEMORY_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("BaseAddress", PVOID),
        ("AllocationBase", PVOID),
        ("AllocationProtect", DWORD),
        ("RegionSize", SIZE_T),
        ("State", DWORD),
        ("Protect", DWORD),
        ("Type", DWORD),
        ]  
class MEMORY_BASIC_INFORMATION64(Structure):
    _fields_ = [('BaseAddress', c_ulonglong),
     ('AllocationBase', c_ulonglong),
     ('AllocationProtect', DWORD),
     ('alignement1', DWORD),
     ('RegionSize', c_ulonglong),
     ('State', DWORD),
     ('Protect', DWORD),
     ('Type', DWORD),
     ('alignement2', DWORD)]


#定义MEMORY_BASIC_INFORMATION END
    
    
    
    
    
    
    
    
     