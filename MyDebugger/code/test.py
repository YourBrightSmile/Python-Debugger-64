# -*- coding: utf-8 -*- 
import my_debugger
from ctypes import *

debugger = my_debugger.debugger()
#debugger.load("c:\\WINDOWS\\system32\calc.exe")
pid = input("请输入输入调试进程的pid:")
debugger.attach(int(pid))
# list = debugger.enumerate_threads()
# for thread in list:
#     thread_context = debugger.get_thread_context(thread)
#     print("[*] Dumping registers for thread ID :0x%08x" %thread)
#     print("[**] RIP:0x%08x" %thread_context.Rip)
#     print("[**] RAX:0x%08x" %thread_context.Rax)

printf_address = debugger.func_resolve("msvcrt.dll",b"printf")

print("[*] Address of printf: 0x%08x" %printf_address)
debugger.bp_set(printf_address)
#debugger.bp_set_hw(printf_address,1,0)
#debugger.bp_set_mem(printf_address,2)
debugger.run()
