# -*- coding: utf-8 -*- 
from ctypes import *
from my_debugger_defines import *
import ctypes.wintypes

kernel32 =windll.kernel32
CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [c_void_p]
CloseHandle.restype = c_bool

########CloseHandle 有句柄无效错误 未解决##############

#debugger核心类
class debugger():
    def __init__(self):
        self.debugger_active = False

        self.h_process = None
        self.pid = None
      
        self.h_thread = None
        self.context = None
        
        self.exception = None
        self.exception_address = None
        #存放断点的字典,断点地址:原始数据
        self.breakpoints = {}
        self.hardware_breakpoints = {}
        self.memory_breakpoints = {}
        self.guarded_pages  = []
        
        self.first_breakpoints = True
        
        
        #确定当前系统中默认内存页
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize
        
    def load(self,path_to_exe):
        
        #参数dwCreationFlags中的标志位控制进程的创建方式。
        #如果希望新创建的进程独占一个新的控制台窗口，而不是与父进程公用
        #可以加上标志位 CREATE_NEW_CONSOLE
        
        creation_flags = DEBUG_PROCESS
        
        #实例化结构体
        startupinfo         = STARTUPINFO()
        process_infomation  = PROCESS_INFORMATION() 
        
        #dwFlags控制starupinfo中的变量是否起作用
        #wShowWindow设置窗体显式状态
        startupinfo.dwFlags = 0x1
        startupinfo.wShowWindow = 0x0
        
        #设置结构体STARTUPINFO中的成员变量cb的值
        startupinfo.cb = sizeof(startupinfo)
        
        #CreateProcessW 支持宽字符
        #CreateProcessA 支持窄字符
        if kernel32.CreateProcessW(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   False,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_infomation)):
            
            print("[*] 进程启动成功!")
            print("[*] PID: %d" % process_infomation.dwProcessId)
        else:
            print("[*] Error:0x%08x." % kernel32.GetLastError())
            #%08x 8表示输出8位，0表示位数不够补0，x表示按16进制输出
                
        #保存指向新进程的有效句柄，供后续进程访问使用
        self.h_process = self.open_process(process_infomation.dwProcessId)
    def open_process(self,pid):
        #打开进程,并返回进程句柄
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS,False,pid)
        return h_process
    
    #附加到进程
    def attach(self,pid):
        
        self.h_process = self.open_process(pid)

        #尝试附加到进程，若附加失败，则输出提示信息后返回
        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
            #self.run()
            
        else:
            print ("[*] 无法附加到进程 [%d] - %s" % (int(pid), FormatError(kernel32.GetLastError())))
    
    def run(self):
        #等待debuged进程中的调试事件
        while self.debugger_active == True:
            self.get_debug_event()
            
            
    def get_debug_event(self):
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE
        if kernel32.WaitForDebugEvent(byref(debug_event),INFINITE):
            #没有对调试线程的处理逻辑时使用
            #input("按按按按按按按按....")
            #self.debugger_active = False
            
            self.h_thread = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(thread_id=debug_event.dwThreadId)
            
            print("Event Code:%s Thread ID: %d" %(debug_event.dwDebugEventCode,debug_event.dwThreadId))
            
            #根据事件码判断异常事件，并检测其类型
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                #获取异常代码 
                self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress
                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print("Access Violation Detected ")
                    print("Exception addr:0x%08x" %self.exception)
                    print("Exception error:%s" %FormatError(kernel32.GetLastError()))
                    input("pause ...")
                #检测到断点,进行处理
                elif self.exception ==  EXCEPTION_BREAKPOINT:
                    print("EXCEPTION_BREAKPOINT")  
                    continue_status = self.exception_handler_breakpoint()
                elif self.exception == EXCEPTION_GUARD_PAGE:
                    print("Guard Page Access Detected")
                    continue_status = self.exception_handler_guard_page()
                elif self.exception == EXCEPTION_SINGLE_STEP:
                    print("Single Steping")
                    continue_status = self.exception_handler_single_step()
                    
            kernel32.ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,continue_status)
    
        
    def detach(self):
        #停止调试
        if kernel32.DebugActiveProcessStop(self.pid):
            print("[*] 完成调试，退出...")
            return True
        else:
            print("Detache Error")
            return False
    
    #线程枚举功能
    ##获取线程句柄
    def open_thread(self,thread_id):   
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS,None,thread_id)
        if h_thread is not None:
            return h_thread
        else:
            print("[*] 获取有效线程句柄失败.")
        
    def enumerate_threads(self):
        thread_entry = THTREADENTRY32()
        thread_list = []
        
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,self.pid)
        if snapshot is not None:
            #正确设置结构体大小，否则会调用失败
            thread_entry.dwSize = sizeof(thread_entry)
            success = kernel32.Thread32First(snapshot,byref(thread_entry))
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(snapshot,byref(thread_entry))
            
            kernel32.CloseHandle(snapshot)
            return thread_list
        else:
            return False
    
    ##获取线程上下文信息(寄存器信息)
    def get_thread_context(self,thread_id=None,h_thread=None):
        
        #64位context
        context = WOW64_CONTEXT()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS
        
        #获取线程句柄
        if h_thread is None:
            self.h_thread = self.open_thread(thread_id)
            
        if kernel32.GetThreadContext(self.h_thread,byref(context)):
            #句柄无效???
            #CloseHandle(self.h_thread)
            return context
        else:
            print("[*] 获取线程上下文信息失败. Error info:%s" %(FormatError(kernel32.GetLastError())))
            return False
        
    
    
            
         
    #读写进程内存函数
    ##读
    def read_process_memory(self,address,length): 
        
        data = b""
        #可改变内容的字符串
        #create_string_buffer("Hello", 10)  # create a 10 byte buffer 
        
        read_buf = create_string_buffer(length)
        count = c_ulong(0)
        ReadProcessMemory = kernel32.ReadProcessMemory
        ReadProcessMemory.argtypes = [HANDLE,LPCVOID,LPVOID,c_size_t,POINTER(c_ulong)]
        ReadProcessMemory.restype = c_bool
        if not ReadProcessMemory(self.h_process,
                                          address,
                                          read_buf,
                                          length,byref(count)):
            return False
        else:
            data += read_buf.raw
            return data
    ##写
    def write_process_memory(self,address,data):
        count = c_ulong(0)
        length = len(data)
        #TODO
        WriteProcessMemory = kernel32.WriteProcessMemory
        WriteProcessMemory.argtypes = [HANDLE,LPVOID,LPCVOID,c_size_t,POINTER(c_ulong)]
        WriteProcessMemory.restype = c_bool
        if not WriteProcessMemory(self.h_process,address,data,length,byref(count)):
            return False
        else:
            return True
    #设置断点
    ##设置软断点
    def bp_set(self,address):
        print("[*] Set Breakpoint：0x%08x" %address)
        
        if not self.breakpoints.__contains__(address):

            #保存原始数据
            original_byte = self.read_process_memory(address,1)
            if original_byte != False:
                self.write_process_memory(address,b'\xCC')
                self.breakpoints[address] = (original_byte)
                return True
            else:
                return False
    #软中断处理程序
    def exception_handler_breakpoint(self):
        print("[*] Inside breakpoint handler...")
        print("[*] Exception Breakpoint address: 0x%08x" %self.exception_address)
        
        if not self.breakpoints.__contains__(self.exception_address):
            
            if self.first_breakpoints==True:
                self.first_breakpoints = False
                print("[*] Hit the first breakpoint...")
                return DBG_CONTINUE
        else:
            print("[*] Hit the user define breakpoint")
            flag = self.write_process_memory(self.exception_address, self.breakpoints[self.exception_address])
            #还要重新设置EIP
            self.context = self.get_thread_context(h_thread=self.h_thread)
            self.context.Rip -= 1
            kernel32.SetThreadContext(self.h_thread,byref(self.context))
            
            return DBG_CONTINUE
        
           
    ##解析函数地址
    def func_resolve(self,dll,function):
        
        #使用argtypes和restype指定参数与返回值的类型，默认是c_int
        GetModuleHandle = kernel32.GetModuleHandleW
        GetModuleHandle.argtypes = [c_wchar_p] #因为GetModuleHandleW有宽字符版本，所以可以传入宽字符
        GetModuleHandle.restype = POINTER(c_void_p)
        handle = GetModuleHandle(dll)
        
        #GetProcAddress没有宽字符版本，这里的function传入bytes类型
        GetProcAddress = windll.kernel32.GetProcAddress
        GetProcAddress.argtypes = [c_void_p, c_char_p] #窄字符只占一个字节，所以使用char
        GetProcAddress.restype = c_void_p
        
        address = GetProcAddress(handle,function)
        
        
        print("AAAAAAAAAAAAAAAAA:%s" %FormatError(kernel32.GetLastError()))
        print(handle)
        CloseHandle(handle)
        print("AAAAAAAAAAAAAAAAA:%s" %FormatError(kernel32.GetLastError()))
        print(handle)
        return address
    
    ##设置硬件断点
    def bp_set_hw(self,address,length,condition):
        print("[*] Set Hardware Breakpoint...")
        #检测硬件长度是否有效
        if length not in (1,2,4):
            return False
        else:
            length -= 1
        
        #检测硬件断点的触发条件是否有效
        if condition not in (HW_ACCESS,HW_EXECUTE,HW_WRITE):
            return False
        #检测是否存在空置的调试寄存器槽
        if not self.hardware_breakpoints.__contains__(0):
            available = 0 
        elif not self.hardware_breakpoints.__contains__(1):
            available = 1
        elif not self.hardware_breakpoints.__contains__(2):
            available = 2 
        elif not self.hardware_breakpoints.__contains__(3):
            available = 3
        else:
            return False
        #在每一个线程环境中设置调试寄存器
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)
            
            #设置DR7中的相应标志位来激活断点
            context.Dr7 |= 1 << (available * 2)
            
            #将断点地址放入寄存器
            if available == 0:
                context.Dr0 = address
            elif available == 1:
                context.Dr1 = address
            elif available == 1:
                context.Dr2 = address
            elif available == 1:
                context.Dr3 = address
            #设置硬件断点触发条件
            context.Dr7 |= condition << ((available*4)+ 16)
            
            #设置硬件断点的长度
            context.Dr7 |= condition << ((available*4)+ 18)
            
            #提交断点改动后的上下文信息
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread,byref(context))
            
        #更新内部的硬件断点
        self.hardware_breakpoints[available] = {address,length,condition}
        return True    
    ##移除硬件断点
    def bp_del_hw(self,slot):
        i=0     
        #为所有线程移出断点
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)  
            
            #通过重设标志位来清除硬件断点
            context.Dr7 &= ~(1 << (slot)*2)
            
            #将断点地址清0
            if slot == 0:
                context.Dr0 = 0x00000000
            elif slot == 1:
                context.Dr1 = 0x00000000
            elif slot == 2:
                context.Dr2 = 0x00000000
            elif slot == 3:
                context.Dr3 = 0x00000000
            
            #清空断点触发条件标志位
            context.Dr7 &= ~(3 <<((slot*4) + 16))
            #清空断点长度标志位
            context.Dr7 &= ~(3 <<((slot*4) + 18))
            
            #提交移出断点后的线程上下文
            h_thread = self.open_thread(thread_id)
            kernel32.SetThreadContext(h_thread,byref(context))
        #将断点从内部断点列表中移出
        del self.hardware_breakpoints[slot]
        return True
    #单步处理程序
    def exception_handler_single_step(self):
        print("[*] Inside Single Step breakpoint handler...")
        print("[*] Exception  address: 0x%08x" %self.exception_address)
        #根据Dr6来判断单步事件触发原因
        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.__contains__(0):
            slot = 0
        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.__contains__(1):
             slot = 1
        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.__contains__(2):
             slot = 2
        elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.__contains__(4):
             slot = 3
        else:
            #这个INT1断点并非由硬件断点所引发
            continue_status = DBG_EXCEPTION_NOT_HANDLED
        #从断点列表中移出断点
        if self.bp_del_hw(slot):
            continue_status = DBG_CONTINUE
            print("[*] remove hardware breakpoint...")
        else:
            print("[*] remove hardware breakpoint failed. ")
        return continue_status        
    ##内存断点
    def bp_set_mem(self,address,size):      
        print("[*] Set Mem Breakpoint ...")
        #使用64位的MEMORY_BASIC_INFORMATION64结构体
        mbi = MEMORY_BASIC_INFORMATION64()
        VirtualQueryEx = kernel32.VirtualQueryEx
        VirtualQueryEx.argtypes = [HANDLE, LPCVOID, POINTER(MEMORY_BASIC_INFORMATION64), c_size_t]
        VirtualQueryEx.restype = c_size_t 
        #若函数调用未返回一个完整的MEMORY_BASIC_INFORMATION结构体则返回False
        if VirtualQueryEx(self.h_process,
                address,
                byref(mbi),
                sizeof(mbi)) < sizeof(mbi): 
            print("error : 0x%08x" %kernel32.GetLastError())
            return False  
         
        current_page = mbi.BaseAddress
        #对整个内存断点所覆盖到的所有内存页设置权限
        while current_page <= address + size:
            #将这些内存页记录在列表中，与debugee进程自设的保护页区别开来
            self.guarded_pages.append(current_page)
            old_protection = c_ulong(0)
            VirtualProtectEx = kernel32.VirtualProtectEx
            VirtualProtectEx.argtypes = [HANDLE,LPVOID,c_size_t,DWORD,POINTER(c_ulong)]
            VirtualProtectEx.restype = c_bool
            if not VirtualProtectEx(self.h_process,current_page,size,mbi.Protect | PAGE_GUARD,byref(old_protection)):
                return False
            #以系统内存页大小为步长，递增断点区域
            current_page += self.page_size
        #将内存断点记录在全局性列表中
        self.memory_breakpoints[address] = (address,size,mbi)
        return True
    #内存断点处理程序
    def exception_handler_guard_page(self):        
        print("[*] Inside Guard Page handler...")
        print("[*] Exception  address: 0x%08x" %self.exception_address)     
        return DBG_CONTINUE        
            
    