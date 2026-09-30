
import ctypes
import ctypes.wintypes as wt
from datetime import datetime
import time

class SYSTEMTIME(ctypes.Structure):
    _fields_ = [
        ("wYear", wt.WORD),
        ("wMonth", wt.WORD),
        ("wDayOfWeek", wt.WORD),
        ("wDay", wt.WORD),
        ("wHour", wt.WORD),
        ("wMinute", wt.WORD),
        ("wSecond", wt.WORD),
        ("wMilliseconds", wt.WORD),
    ]

def set_system_time(dt):
    st = SYSTEMTIME()
    st.wYear = dt.year
    st.wMonth = dt.month
    st.wDay = dt.day
    st.wHour = dt.hour
    st.wMinute = dt.minute
    st.wSecond = dt.second
    st.wMilliseconds = 0
    k = ctypes.WinDLL('kernel32', use_last_error=True)
    return k.SetLocalTime(ctypes.byref(st)) != 0

time.sleep(180)

original = datetime(2026, 8, 25, 
                   15, 58, 2)
set_system_time(original)
print("Time restored to:", original)
