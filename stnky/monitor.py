import ctypes, ctypes.wintypes as wt, time, struct, os, sys as _sys

if getattr(_sys, 'frozen', False):
    BASE = os.path.join(os.path.dirname(_sys.executable), 'app')
else:
    BASE = os.path.dirname(os.path.abspath(__file__))
    _sys.path.insert(0, os.path.join(BASE, 'Tools'))
import slow_hook as _ih

k = ctypes.WinDLL('kernel32', use_last_error=True)
k.OpenProcess.restype = wt.HANDLE
k.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k.CloseHandle.argtypes = [wt.HANDLE]
k.CreateToolhelp32Snapshot.restype = wt.HANDLE
k.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k.Process32FirstW.argtypes = [wt.HANDLE, ctypes.c_void_p]
k.Process32NextW.argtypes = [wt.HANDLE, ctypes.c_void_p]
k.Module32FirstW.argtypes = [wt.HANDLE, ctypes.c_void_p]
k.Module32NextW.argtypes = [wt.HANDLE, ctypes.c_void_p]
k.VirtualAllocEx.restype = ctypes.c_void_p
k.VirtualAllocEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD]
k.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k.VirtualProtectEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, ctypes.POINTER(wt.DWORD)]

def _rd(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    k.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    return buf.raw[:n.value]

def _wr(h, addr, data):
    buf = ctypes.create_string_buffer(data, len(data))
    w = ctypes.c_size_t(0)
    return k.WriteProcessMemory(h, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(w))

def log(msg):
    try:
        with open(os.path.join(BASE, 'monitor.log'), 'a', encoding='utf-8') as f:
            f.write(f"{time.strftime('%H:%M:%S')} {msg}\n")
    except Exception:
        pass

def enum_pids(name):
    name = name.lower(); out = []
    class PE(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wt.DWORD),
                    ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]
    snap = k.CreateToolhelp32Snapshot(0x2, 0)
    if snap and snap != 0xffffffffffffffff:
        pe = PE(); pe.dwSize = ctypes.sizeof(pe)
        if k.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                if str(pe.szExeFile).lower() == name:
                    out.append(pe.th32ProcessID)
                if not k.Process32NextW(snap, ctypes.byref(pe)):
                    break
        k.CloseHandle(snap)
    return out

def enum_modules(pid):
    out = []
    class ME(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD), ("th32ProcessID", wt.DWORD),
                    ("GlblcntUsage", wt.DWORD), ("ProccntUsage", wt.DWORD),
                    ("modBaseAddr", ctypes.c_void_p), ("modBaseSize", wt.DWORD),
                    ("hModule", ctypes.c_void_p), ("szModule", ctypes.c_wchar * 256),
                    ("szExePath", ctypes.c_wchar * 260)]
    snap = k.CreateToolhelp32Snapshot(0x8, pid)
    if snap and snap != 0xffffffffffffffff:
        me = ME(); me.dwSize = ctypes.sizeof(me)
        if k.Module32FirstW(snap, ctypes.byref(me)):
            while True:
                out.append((str(me.szModule), me.modBaseAddr, me.modBaseSize))
                if not k.Module32NextW(snap, ctypes.byref(me)):
                    break
        k.CloseHandle(snap)
    return out

def main():
    try:
        v = _sys.getwindowsversion(); winver = f"{v.major}.{v.minor}.{v.build}"
    except Exception:
        winver = '?'
    try:
        import slow_hook as _sh; capok = _sh._MD is not None
    except Exception as e:
        capok = f'import-err:{e!r}'
    try:
        log(f"selftest: {_ih.selftest()}")
    except Exception as e:
        log(f"selftest EXC: {e!r}")
    log(f"=== monitor started === frozen={getattr(_sys,'frozen',False)} win={winver} capstone={capok}")
    # Keep retrying each game process until every timer source that CAN be hooked IS hooked.
    # A single pass can miss a super-hot API because a thread was executing its exact prologue
    # bytes at suspend time (thread-in-prologue) -> that miss is transient, so we re-attempt
    # only the still-unhooked targets on later passes (threads move) until nothing retryable
    # remains or we exhaust MAX_ATTEMPTS. This is what makes the 5-min hook land for EVERYONE
    # regardless of per-machine thread timing.
    MAX_ATTEMPTS = 150
    hooked = set(); opened = {}; done = {}; attempts = {}
    while True:
        try:
            targets = enum_pids('javaw.exe') + enum_pids('java.exe')
            live = set(targets)
            # forget processes that exited so a re-launched game re-hooks cleanly
            for gone in [p for p in list(opened) if p not in live]:
                try: k.CloseHandle(opened[gone])
                except Exception: pass
                opened.pop(gone, None); done.pop(gone, None); attempts.pop(gone, None)
            spin = False
            for pid in targets:
                if pid in hooked:
                    continue
                h = opened.get(pid)
                if h is None:
                    h = k.OpenProcess(0x0438, False, pid)
                    if not h:
                        # elevated game vs non-elevated monitor, or AV -> log once, keep trying
                        if attempts.get(('open', pid), 0) == 0:
                            log(f"OpenProcess FAILED pid={pid} err={ctypes.get_last_error()} (is the game elevated? monitor needs /rl highest)")
                        attempts[('open', pid)] = attempts.get(('open', pid), 0) + 1
                        continue
                    opened[pid] = h
                nb = None; nsz = 0
                for name, base, size in enum_modules(pid):
                    if 'nacre' in name.lower():
                        nb = base; nsz = size; break
                if not nb:
                    continue
                d = done.setdefault(pid, set())
                n = attempts.get(pid, 0) + 1; attempts[pid] = n
                if n == 1:
                    log(f"nacre found pid={pid} base={hex(nb)} size={hex(nsz)} -> installing hooks")
                try:
                    res = _ih.install(h, nb, nsz, done=d)
                except Exception as e:
                    import traceback as _tb
                    log(f"slow-hook EXCEPTION pid={pid} attempt={n}: {e!r}\n{_tb.format_exc()}")
                    res = []
                newly_ok = 0; retry_left = 0
                for r in res:
                    nm = r[0]; ok = r[1] is True; detail = r[2] if len(r) > 2 else ''
                    if ok:
                        if nm not in d: d.add(nm); newly_ok += 1
                    elif _ih.is_retryable(detail):
                        retry_left += 1
                    if n == 1 or ok or _ih.is_retryable(detail):
                        log(f"  [a{n}] hook {nm}: {'OK' if ok else 'SKIP/FAIL'} :: {detail}")
                if newly_ok:
                    log(f"slow-hook nacre@{hex(nb)} pid={pid} attempt={n} newly_ok={newly_ok} done={len(d)} retry_left={retry_left}")
                # Done when no retryable miss remains and we hooked at least one thing,
                # or we've tried too many times (give up gracefully, keep what we got).
                if (retry_left == 0 and d) or n >= MAX_ATTEMPTS:
                    log(f"slow-hook pid={pid} FINALIZED after {n} attempts, hooked={sorted(d)}")
                    hooked.add(pid)
                    try: k.CloseHandle(h); opened.pop(pid, None)
                    except Exception: pass
                else:
                    spin = True   # still chasing a transient miss -> retry fast so threads move
            time.sleep(0.03 if spin else 0.3)
        except Exception as e:
            log(f"loop error: {e!r}")
            time.sleep(0.3)

if __name__ == '__main__':
    main()