#coding=utf-8
from ctypes import *
import time


msvcrt = cdll.msvcrt
count = 0

while 1:
    msvcrt.printf(b"loop count: %d \n" %count)
    time.sleep(2)
    count+=1