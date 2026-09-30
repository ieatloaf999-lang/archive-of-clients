import ctypes, ctypes.wintypes as wt, os, sys, time, subprocess, threading, atexit, signal, struct, json, ssl, http.server, calendar, tempfile, uuid
from datetime import datetime, timedelta

if getattr(sys, 'frozen', False):
    BASE = os.path.join(os.path.dirname(sys.executable), 'app')
else:
    BASE = os.path.dirname(os.path.abspath(__file__))
if __name__ == '__main__' and '--monitor' in sys.argv:
    sys.path.insert(0, os.path.join(BASE, 'Tools'))
    import monitor
    monitor.main()
    sys.exit(0)
if getattr(sys, 'frozen', False) and __name__ == '__main__':
    try: _admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception: _admin = 0
    if not _admin:
        _args = ' '.join(f'"{a}"' if ' ' in a else a for a in sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, _args, None, 1)
        sys.exit(0)
os.chdir(BASE)
HOSTS = os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'drivers', 'etc', 'hosts')
HOSTMAP = [("api.stinky.top", "127.0.0.2"), ("api.slinky.gg", "127.0.0.1")]
STATUS_FILE = os.path.join(BASE, 'activation.txt')   # sacrificial --debugger child -> main handshake
LEASE_T = 1787644550
KW = int(open('kw_rva.txt').read().strip(), 16); RIDBP = 0x16ab31; NONCEBP = 0x16ac53
SECRET_BP = 0x16dcf0; SECRET = bytes.fromhex("d3a02876f4a48edf875a2f1a19e44888f2995ff53a8bc02b9863d157927aa547")
Kpriv = open('capture_my_priv.bin','rb').read(); LICENSE = open('license.txt').read().strip()
NONCE_B64 = open('cap_nonce_b64.txt').read().strip().encode(); RID_B64 = open('cap_rid_b64.txt').read().strip().encode()
k = ctypes.WinDLL('kernel32', use_last_error=True); nt = ctypes.WinDLL('ntdll')

# The system clock is set to Aug-25 while Stinky runs. This is REQUIRED, not cosmetic:
# hook_time only freezes Stinky's 4 wall-clock APIs, but Stinky also reads UNHOOKED time
# sources (KUSER_SHARED_DATA, GetTickCount, QueryPerformanceCounter). If the real clock is
# not Aug-25, the frozen and unfrozen sources disagree and Stinky crashes the moment it
# starts its LAS -> "443 doesn't come up". Keeping the real clock at Aug-25 makes every time
# source agree. It is restored to the real time in cleanup() when this window closes.
TARGET_TIME = datetime(2026, 8, 25, 15, 56, 0)
class SYSTEMTIME(ctypes.Structure):
    _fields_=[("wYear",wt.WORD),("wMonth",wt.WORD),("wDayOfWeek",wt.WORD),("wDay",wt.WORD),
              ("wHour",wt.WORD),("wMinute",wt.WORD),("wSecond",wt.WORD),("wMilliseconds",wt.WORD)]
def set_system_time(dt):
    st=SYSTEMTIME(); st.wYear=dt.year; st.wMonth=dt.month; st.wDay=dt.day
    st.wHour=dt.hour; st.wMinute=dt.minute; st.wSecond=dt.second; st.wMilliseconds=0
    return k.SetLocalTime(ctypes.byref(st))!=0
def get_system_time():
    st=SYSTEMTIME(); k.GetLocalTime(ctypes.byref(st))
    return datetime(st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond)

def process_exists(*names):
    """Return whether any process image name is currently running."""
    wanted = {n.lower() for n in names}
    try:
        out = subprocess.check_output(
            ['tasklist', '/fo', 'csv', '/nh'],
            text=True, encoding='mbcs', errors='replace',
            creationflags=subprocess.CREATE_NO_WINDOW)
        return any(line.split(',', 1)[0].strip('"').lower() in wanted
                   for line in out.splitlines() if line)
    except Exception:
        return False

def find(name):
    for p in (os.path.join(BASE,'stlinky',name), os.path.join(BASE,name)):
        if os.path.exists(p): return p
    return None
STINKY = find('Stinky.exe'); SDIR = os.path.dirname(STINKY) if STINKY else ''

class ST(ctypes.Structure):
    _fields_=[("y",wt.WORD),("mo",wt.WORD),("dw",wt.WORD),("d",wt.WORD),("h",wt.WORD),("mi",wt.WORD),("s",wt.WORD),("ms",wt.WORD)]
def get_unix():
    st=ST(); k.GetSystemTime(ctypes.byref(st)); return calendar.timegm((st.y,st.mo,st.d,st.h,st.mi,st.s,0,0,0))
def hosts_add():
    try: lines = open(HOSTS,'r',encoding='utf-8',errors='replace').read().splitlines()
    except Exception: lines = []
    lines = [l for l in lines if 'stinky' not in l.lower() and 'slinky' not in l.lower()]
    for host, ip in HOSTMAP: lines.append(ip + " " + host)
    open(HOSTS,'w',encoding='utf-8').write("\n".join(lines) + "\n")
def hosts_remove():
    try:
        lines = open(HOSTS,'r',encoding='utf-8',errors='replace').read().splitlines()
        open(HOSTS,'w',encoding='utf-8').write("\n".join(l for l in lines if 'stinky' not in l.lower() and 'slinky' not in l.lower()) + "\n")
    except Exception as e: print("hosts cleanup failed:", e)
def cert_install(): subprocess.run(['certutil','-addstore','-f','ROOT',os.path.join(BASE,'mock_cert.pem')], capture_output=True)
def cert_remove():  subprocess.run(['certutil','-delstore','ROOT','api.stinky.top'], capture_output=True)

def hook_time(hProc):
    FT=(LEASE_T+11644473600)*10_000_000
    # so: for the pointer-taking APIs (GetSystemTimeAsFileTime / GetSystemTimePreciseAsFileTime /
    #     NtQuerySystemTime) the OUT pointer is in rcx -> mov rax,FT; mov [rcx],rax; xor eax,eax; ret
    so=b'\x48\xB8'+FT.to_bytes(8,'little')+b'\x48\x89\x01\x48\x31\xC0\xC3'
    # sr: RtlGetSystemTimePrecise(VOID) returns LARGE_INTEGER BY VALUE in rax and takes NO args.
    #     It must NOT touch rcx -> mov rax,FT; ret. (The old stub did `mov [rcx],rax`, writing 8
    #     bytes to whatever garbage rcx held at the call site -> access violation on machines where
    #     rcx pointed at non-writable memory, crashing Stinky exactly as it started its LAS.)
    sr=b'\x48\xB8'+FT.to_bytes(8,'little')+b'\xC3'
    k32=k.GetModuleHandleW('kernel32.dll'); ntd=k.GetModuleHandleW('ntdll.dll')
    n=0
    for mod,name,stub in [(k32,b'GetSystemTimeAsFileTime',so),(k32,b'GetSystemTimePreciseAsFileTime',so),(ntd,b'NtQuerySystemTime',so),(ntd,b'RtlGetSystemTimePrecise',sr)]:
        if not mod: continue
        a=k.GetProcAddress(mod,name)
        if not a: continue
        old=wt.DWORD(0)
        if k.VirtualProtectEx(hProc,ctypes.c_void_p(a),len(stub),0x40,ctypes.byref(old)):
            w=ctypes.c_size_t(0)
            k.WriteProcessMemory(hProc,ctypes.c_void_p(a),stub,len(stub),ctypes.byref(w))
            k.VirtualProtectEx(hProc,ctypes.c_void_p(a),len(stub),old.value,ctypes.byref(old))
            n+=1
    return n


CAP = json.load(open(os.path.join(BASE,'capture_response.json'), encoding='utf-8')); RESP = json.dumps(CAP).encode()
class H(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*a): pass
    def _h(self):
        n=int(self.headers.get('Content-Length',0)); self.rfile.read(n) if n else b''
        out = RESP if any(p in self.path for p in ('/v3/activate','/v3/heartbeat','/v3/evidence')) else b'{"error":"not_found"}'
        self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(out)))
        self.send_header('Cache-Control','no-store'); self.send_header('Connection','close'); self.end_headers(); self.wfile.write(out); self.close_connection=True
    do_POST=_h; do_GET=_h
def run_mock():
    try:
        srv=http.server.ThreadingHTTPServer(('127.0.0.2',443),H)
        c=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(os.path.join(BASE,'mock_cert.pem'),os.path.join(BASE,'mock_key.pem'))
        srv.socket=c.wrap_socket(srv.socket,server_side=True); state['mock']=srv
        diag("mock server bound OK on 127.0.0.2:443")
        srv.serve_forever()
    except Exception as e:
        errno = getattr(e, 'errno', getattr(e, 'winerror', '?'))
        hint = {10048:'PORT 443 ALREADY IN USE (another app/service holds it)',
                10013:'ACCESS DENIED (firewall/AV blocking bind, or not admin)'}.get(errno, '')
        diag(f"FATAL mock bind FAILED on 127.0.0.2:443 err={errno} {e!r} {hint}")

k.GetThreadContext.restype=wt.BOOL; k.GetThreadContext.argtypes=[wt.HANDLE,ctypes.c_void_p]
k.SetThreadContext.restype=wt.BOOL; k.SetThreadContext.argtypes=[wt.HANDLE,ctypes.c_void_p]
k.OpenThread.restype=wt.HANDLE
k.CreateToolhelp32Snapshot.restype=wt.HANDLE; k.CreateToolhelp32Snapshot.argtypes=[wt.DWORD,wt.DWORD]
k.Thread32First.argtypes=[wt.HANDLE,ctypes.c_void_p]; k.Thread32Next.argtypes=[wt.HANDLE,ctypes.c_void_p]
k.GetModuleHandleW.restype=ctypes.c_void_p; k.GetModuleHandleW.argtypes=[wt.LPCWSTR]
k.GetProcAddress.restype=ctypes.c_void_p; k.GetProcAddress.argtypes=[ctypes.c_void_p,ctypes.c_char_p]
k.VirtualProtectEx.argtypes=[wt.HANDLE,ctypes.c_void_p,ctypes.c_size_t,wt.DWORD,ctypes.POINTER(wt.DWORD)]
k.OpenProcess.restype=wt.HANDLE; k.OpenProcess.argtypes=[wt.DWORD,wt.BOOL,wt.DWORD]
k.VirtualAllocEx.restype=ctypes.c_void_p; k.VirtualAllocEx.argtypes=[wt.HANDLE,ctypes.c_void_p,ctypes.c_size_t,wt.DWORD,wt.DWORD]
k.Module32First.argtypes=[wt.HANDLE,ctypes.c_void_p]; k.Module32Next.argtypes=[wt.HANDLE,ctypes.c_void_p]
k.Process32First.argtypes=[wt.HANDLE,ctypes.c_void_p]; k.Process32Next.argtypes=[wt.HANDLE,ctypes.c_void_p]
class SA(ctypes.Structure): _fields_=[("n",wt.DWORD),("sd",ctypes.c_void_p),("inh",wt.BOOL)]
class SI(ctypes.Structure):
    _fields_=[("cb",wt.DWORD),("r1",wt.LPWSTR),("r2",wt.LPWSTR),("r3",wt.LPWSTR),("dwX",wt.DWORD),("dwY",wt.DWORD),("dwXS",wt.DWORD),("dwYS",wt.DWORD),("dwXC",wt.DWORD),("dwYC",wt.DWORD),("dwFill",wt.DWORD),("dwFlags",wt.DWORD),("wShow",wt.WORD),("cbR",wt.WORD),("lpR",ctypes.c_void_p),("hIn",wt.HANDLE),("hOut",wt.HANDLE),("hErr",wt.HANDLE)]
class PI(ctypes.Structure): _fields_=[("hP",wt.HANDLE),("hT",wt.HANDLE),("pid",wt.DWORD),("tid",wt.DWORD)]
class PBI(ctypes.Structure): _fields_=[("a",ctypes.c_void_p),("Peb",ctypes.c_void_p),("b",ctypes.c_void_p*2),("c",ctypes.c_void_p),("d",ctypes.c_void_p)]
class SIEX(ctypes.Structure): _fields_=[("si",SI),("lpAttributeList",ctypes.c_void_p)]
class PE32(ctypes.Structure):
    _fields_=[("dwSize",wt.DWORD),("cntUsage",wt.DWORD),("th32ProcessID",wt.DWORD),("th32DefaultHeapID",ctypes.c_void_p),
              ("th32ModuleID",wt.DWORD),("cntThreads",wt.DWORD),("th32ParentProcessID",wt.DWORD),
              ("pcPriClassBase",ctypes.c_long),("dwFlags",wt.DWORD),("szExeFile",ctypes.c_wchar*260)]
k.Process32FirstW.argtypes=[wt.HANDLE,ctypes.c_void_p]; k.Process32NextW.argtypes=[wt.HANDLE,ctypes.c_void_p]
k.InitializeProcThreadAttributeList.restype=wt.BOOL; k.InitializeProcThreadAttributeList.argtypes=[ctypes.c_void_p,wt.DWORD,wt.DWORD,ctypes.POINTER(ctypes.c_size_t)]
k.UpdateProcThreadAttribute.restype=wt.BOOL; k.UpdateProcThreadAttribute.argtypes=[ctypes.c_void_p,wt.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.c_void_p]
k.DeleteProcThreadAttributeList.argtypes=[ctypes.c_void_p]
def find_pid(name):
    name=name.lower(); snap=k.CreateToolhelp32Snapshot(0x2,0); found=0
    if snap and snap!=ctypes.c_void_p(-1).value:
        pe=PE32(); pe.dwSize=ctypes.sizeof(pe)
        if k.Process32FirstW(snap,ctypes.byref(pe)):
            while True:
                if pe.szExeFile.lower()==name: found=pe.th32ProcessID; break
                if not k.Process32NextW(snap,ctypes.byref(pe)): break
        k.CloseHandle(snap)
    return found

def run_stinky():
    DBG_ONLY=0x2; USESTD=0x100; DBG_CONTINUE=0x00010002; DBG_EXC_NH=0x80010001
    k.DebugSetProcessKillOnExit(False)
    sa=SA(); sa.n=ctypes.sizeof(sa); sa.inh=True
    hInR=wt.HANDLE(); hInW=wt.HANDLE(); hOR=wt.HANDLE(); hOW=wt.HANDLE()
    k.CreatePipe(ctypes.byref(hInR),ctypes.byref(hInW),ctypes.byref(sa),0); k.CreatePipe(ctypes.byref(hOR),ctypes.byref(hOW),ctypes.byref(sa),0)
    k.SetHandleInformation(hInW,0x1,0); k.SetHandleInformation(hOR,0x1,0)
    # run_stinky is executed in a SACRIFICIAL --debugger subprocess, never in the main
    # launcher: Stinky's VMProtect anti-debug TerminateProcess'es its debugger (== its parent,
    # because DEBUG_ONLY_THIS_PROCESS forces PPID = debugger) ~2s after detach. Letting that
    # kill land on this throwaway process (which has already finished its job) keeps the real
    # launcher alive to run cleanup / print READY.
    si=SI(); si.cb=ctypes.sizeof(si); si.dwFlags=USESTD; si.hIn=hInR; si.hOut=hOW; si.hErr=hOW; pi=PI()
    if not k.CreateProcessW(STINKY,None,None,None,True,DBG_ONLY,None,SDIR,ctypes.byref(si),ctypes.byref(pi)):
        diag(f"FATAL Stinky CreateProcess FAILED err={ctypes.get_last_error()} exe={STINKY} dir={SDIR}")
        try: open(STATUS_FILE,'w').write("FAIL createprocess")
        except Exception: pass
        return
    pid=pi.pid; state['stinky_pid']=pid; k.CloseHandle(hInR); k.CloseHandle(hOW)
    def drain():
        b=ctypes.create_string_buffer(4096); n=wt.DWORD(0)
        with open(os.path.join(BASE,'stinky_stdout.log'),'wb') as f:
            while k.ReadFile(hOR,b,4096,ctypes.byref(n),None) and n.value:
                state['out']+=b.raw[:n.value]; f.write(b.raw[:n.value]); f.flush()
    threading.Thread(target=drain,daemon=True).start()
    def feed():
        time.sleep(3.0); d=(LICENSE+"\r\n").encode(); wr=wt.DWORD(0)
        for _ in range(12):
            if state.get('stinky_ready'): break   # stop feeding once activated so Stinky moves on to start its LAS
            k.WriteFile(hInW,d,len(d),ctypes.byref(wr),None); time.sleep(4)
    threading.Thread(target=feed,daemon=True).start()
    pbi=PBI(); rl=ctypes.c_ulong(0); nt.NtQueryInformationProcess(pi.hP,0,ctypes.byref(pbi),ctypes.sizeof(pbi),ctypes.byref(rl)); peb=pbi.Peb
    def clear_peb():
        z=ctypes.c_byte(0); w=ctypes.c_size_t(0); k.WriteProcessMemory(pi.hP,ctypes.c_void_p(peb+0x2),ctypes.byref(z),1,ctypes.byref(w))
        g=ctypes.c_uint(0); k.WriteProcessMemory(pi.hP,ctypes.c_void_p(peb+0xBC),ctypes.byref(g),4,ctypes.byref(w))
    def rmem(a,n):
        b=ctypes.create_string_buffer(n); rd=ctypes.c_size_t(0); k.ReadProcessMemory(pi.hP,ctypes.c_void_p(a),b,n,ctypes.byref(rd)); return b.raw[:rd.value]
    def wmem(a,d):
        w=ctypes.c_size_t(0); return k.WriteProcessMemory(pi.hP,ctypes.c_void_p(a),d,len(d),ctypes.byref(w))
    def patch_time():
        n=hook_time(pi.hP)
        if n: print(f"[time-hook] Stinky pid={pid} hooked {n} time APIs", flush=True)
    raw=ctypes.create_string_buffer(1600); ctxaddr=(ctypes.addressof(raw)+15)&~15
    def getctx(hT):
        ctypes.memset(ctxaddr,0,1232); struct.pack_into('<I',(ctypes.c_char*4).from_address(ctxaddr+0x30),0,0x10001F); return k.GetThreadContext(hT,ctxaddr)
    def cg(o): return struct.unpack_from('<Q',(ctypes.c_char*8).from_address(ctxaddr+o),0)[0]
    def cs(o,v): struct.pack_into('<Q',(ctypes.c_char*8).from_address(ctxaddr+o),0,v)
    def cef(): return struct.unpack_from('<I',(ctypes.c_char*4).from_address(ctxaddr+0x44),0)[0]
    def sef(v): struct.pack_into('<I',(ctypes.c_char*4).from_address(ctxaddr+0x44),0,v)
    def setctx(hT): return k.SetThreadContext(hT,ctxaddr)
    base=[0]; skc=[False]; rid=[False]; non=[False]; dev=[False]; det=[False]; timed=[False]; RBP=0xA0
    def arm(tid):
        if not base[0] or det[0]: return
        hT=k.OpenThread(0x8|0x10,False,tid)
        if hT and getctx(hT): cs(0x48,base[0]+KW); cs(0x50,base[0]+RIDBP); cs(0x58,base[0]+NONCEBP); cs(0x60,base[0]+SECRET_BP); cs(0x70,0x55); setctx(hT)
        if hT: k.CloseHandle(hT)
    def pstr(rbp,off,newb):
        ptr=struct.unpack_from('<Q',rmem(rbp+off,8),0)[0]; ln=struct.unpack_from('<Q',rmem(rbp+off+0x10,8),0)[0]; cap=struct.unpack_from('<Q',rmem(rbp+off+0x18,8),0)[0]
        da=(rbp+off) if cap<16 else ptr
        if len(newb)==ln: wmem(da,newb)
    def patch_secret(addr):
        ptr=struct.unpack_from('<Q',rmem(addr,8),0)[0]; ln=struct.unpack_from('<Q',rmem(addr+8,8),0)[0]
        cur=rmem(ptr,ln) if 0x1000<ptr<0x7fffffffffff and 0<ln<200 else b''
        print(f"   [secret] ptr={hex(ptr)} len={ln} cur={cur.hex()}", flush=True)
        if ln==32 and cur: wmem(ptr,SECRET); print(f"      -> {SECRET.hex()}", flush=True); return True
        return False
    DES=0xB0
    dc=lambda b:struct.unpack_from('<I',b,0)[0]; dpid=lambda b:struct.unpack_from('<I',b,4)[0]; dt=lambda b:struct.unpack_from('<I',b,8)[0]
    dec=lambda b:struct.unpack_from('<I',b,16)[0]; dcb=lambda b:struct.unpack_from('<Q',b,40)[0]
    de=ctypes.create_string_buffer(DES); t0=time.time()
    while time.time()-t0<120:
        if not k.WaitForDebugEvent(de,200): clear_peb(); continue
        code=dc(de.raw); status=DBG_CONTINUE; cur=dt(de.raw)
        if code==3: base[0]=dcb(de.raw); arm(cur)
        elif code==1:
            ec=dec(de.raw)
            if ec==0x80000004 and base[0]:
                hT=k.OpenThread(0x8|0x10,False,cur)
                if getctx(hT):
                    dr6=cg(0x68)
                    if dr6&1 and not skc[0]: wmem(cg(0x88),Kpriv); skc[0]=True; print("[skc] patched", flush=True)
                    elif dr6&2 and not rid[0]: pstr(cg(RBP),0x410,RID_B64); rid[0]=True; print("[rid] patched", flush=True)
                    elif dr6&4 and not non[0]: pstr(cg(RBP),0x430,NONCE_B64); non[0]=True; print("[nonce] patched", flush=True)
                    elif dr6&8 and not dev[0]: print(f"[secret] rip={hex(cg(0xF8))} rdx={hex(cg(0x88))}", flush=True); patch_secret(cg(0x88)); dev[0]=True
                    cs(0x68,0); sef(cef()|0x10000); setctx(hT)
                k.CloseHandle(hT)
            elif ec not in (0x80000003,0x80000004,0x4000001f): status=DBG_EXC_NH
        elif code==5: k.ContinueDebugEvent(dpid(de.raw),cur,DBG_CONTINUE); break
        clear_peb()
        if base[0] and not det[0]:
            if skc[0] and rid[0] and non[0] and dev[0]:
                if not os.environ.get('NOTHOOK'): patch_time()
                th=k.CreateToolhelp32Snapshot(0x4,pid)
                class TE(ctypes.Structure): _fields_=[("sz",wt.DWORD),("cu",wt.DWORD),("tid",wt.DWORD),("opid",wt.DWORD),("bp",ctypes.c_long),("dp",ctypes.c_long),("fl",wt.DWORD)]
                te=TE(); te.sz=ctypes.sizeof(te)
                if k.Thread32First(th,ctypes.byref(te)):
                    while True:
                        if te.opid==pid:
                            hT=k.OpenThread(0x2|0x8|0x10,False,te.tid)
                            if hT:
                                k.SuspendThread(hT)
                                if getctx(hT): cs(0x48,0);cs(0x50,0);cs(0x58,0);cs(0x60,0);cs(0x68,0);cs(0x70,0); setctx(hT)
                                k.ResumeThread(hT); k.CloseHandle(hT)
                        if not k.Thread32Next(th,ctypes.byref(te)): break
                k.CloseHandle(th)
                det[0]=True; k.ContinueDebugEvent(dpid(de.raw),cur,DBG_CONTINUE); time.sleep(0.03); k.DebugActiveProcessStop(pid)
                time.sleep(0.05); clear_peb()
                # Drop every handle we hold to Stinky. VMProtect's post-launch anti-debug can
                # enumerate who holds a handle to it (or its parent) and TerminateProcess them --
                # that is what was killing this launcher ~2s after detach.
                try:
                    k.CloseHandle(pi.hP); k.CloseHandle(pi.hT)
                    diag("closed Stinky process/thread handles to dodge anti-debug kill")
                except Exception as _e:
                    diag(f"handle-close failed: {_e!r}")
                print("[detach] cleared PEB BeingDebugged + NtGlobalFlag", flush=True)
                diag(f"activation OK: breakpoints skc={skc[0]} rid={rid[0]} nonce={non[0]} secret={dev[0]} -> detached; stinky_pid={pid}")
                # Report success to the parent NOW, before Stinky's anti-debug can kill this child.
                try: open(STATUS_FILE,'w',encoding='utf-8').write(f"OK {pid}")
                except Exception: pass
                state['stinky_ready']=True; break
            arm(cur)
        k.ContinueDebugEvent(dpid(de.raw),cur,status)
    # If we never reached a clean detach, tell the parent it failed (the OK case was already
    # written at the detach point, before Stinky's anti-debug can kill this child).
    if not det[0]:
        try: open(STATUS_FILE,'w',encoding='utf-8').write("FAIL "+repr(state['out'][-300:]))
        except Exception: pass

state={'U0':None,'mono0':None,'orig_time':None,'mock':None,'out':b'','stinky_ready':False,'stinky_pid':None,'done':False}
def restore_clock():
    # Put the real clock back. Called from cleanup() AFTER Stinky is killed, so restoring the
    # (now inconsistent) time can't crash a running LAS. Real time = captured original + elapsed.
    if not state.get('orig_time'): return
    try:
        target = state['orig_time'] + timedelta(seconds=time.monotonic() - (state.get('mono0') or time.monotonic()))
        if set_system_time(target): diag(f"system clock restored to real time: {target}")
        else: sync_windows_time()
    except Exception as e:
        diag(f"clock restore failed ({e!r}); trying w32tm"); sync_windows_time()
def sync_windows_time():
    try: subprocess.run(['w32tm','/resync','/force'], capture_output=True, creationflags=0x08000000)
    except Exception: pass
def hard_reset():
    pats = ["*--monitor*", "*monitor.py*"]
    cond = " -or ".join(f"$_.CommandLine -like '{p}'" for p in pats)
    ps = ("$me=$PID;"
          f"Get-CimInstance Win32_Process | Where-Object {{ $_.ProcessId -ne $me -and ({cond}) }} | ForEach-Object {{ Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }};"
          "Get-Process Stinky -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue;"
          "Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }")
    subprocess.run(['powershell','-NoProfile','-Command',ps], capture_output=True)
    subprocess.run(['schtasks','/delete','/tn','StinkyMon','/f'], capture_output=True)
    subprocess.run(['schtasks','/delete','/tn','StinkyDbg','/f'], capture_output=True)
def cleanup():
    dbglog("cleanup called")
    # Only the MAIN process may tear down hosts/cert/servers. A worker (e.g. --monitor)
    # exiting must NEVER remove the hosts mapping -- that used to cause Slinky
    # 'connection refused' when a helper crashed.
    if not IS_MAIN: return
    if state['done']: return
    state['done']=True
    print("\ncleaning up")
    hosts_remove(); print("hosts entries removed")
    cert_remove(); print("mock TLS cert removed")
    if state['mock']:
        try: state['mock'].shutdown()
        except Exception: pass
    hard_reset()                 # kills Stinky first...
    restore_clock()              # ...then it's safe to put the real clock back
    print("done. leftover monitor cleaned; system clock restored.")
IS_MAIN = False
atexit.register(cleanup)
# Closing the console window (the X button), logoff, or shutdown does NOT run Python's atexit,
# so the clock would stay on Aug-25. A Win32 console-control handler restores it on those events.
_CTRL_CB = ctypes.WINFUNCTYPE(wt.BOOL, wt.DWORD)
def _on_console_ctrl(ctrl):          # CTRL_C=0 BREAK=1 CLOSE=2 LOGOFF=5 SHUTDOWN=6
    try: cleanup()                   # restore clock + hosts + cert before we go, for ALL exits
    except Exception: pass
    os._exit(0)
_ctrl_ref = _CTRL_CB(_on_console_ctrl)
try: k.SetConsoleCtrlHandler(_ctrl_ref, True)
except Exception: pass

def dbglog(msg):
    try:
        with open(os.path.join(BASE,'_dbg_exit.log'),'a',encoding='utf-8') as f:
            f.write(f"{time.monotonic():.1f} {msg}\n")
    except Exception: pass

def diag(msg):
    line = f"{time.strftime('%H:%M:%S')} {msg}"
    try: print("[diag]", msg, flush=True)
    except Exception: pass
    try:
        with open(os.path.join(BASE,'diag.log'),'a',encoding='utf-8') as f:
            f.write(line+"\n")
    except Exception: pass

def _who443():
    try:
        ps=("Get-NetTCPConnection -LocalPort 443 -ErrorAction SilentlyContinue | ForEach-Object { "
            "$p=(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName; "
            "\"$($_.LocalAddress):443 $($_.State) pid=$($_.OwningProcess)($p)\" }")
        r=subprocess.run(['powershell','-NoProfile','-Command',ps],capture_output=True,text=True,creationflags=0x08000000)
        return ' | '.join(l.strip() for l in r.stdout.splitlines() if l.strip())[:400] or 'none'
    except Exception as e:
        return f'who443-err:{e!r}'

def _port443():
    import socket
    out=[]
    for ip in ('127.0.0.1','127.0.0.2'):
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try: s.bind((ip,443)); out.append(f"{ip}:443=FREE")
        except OSError as e: out.append(f"{ip}:443=BLOCKED(errno={e.errno})")
        finally:
            try: s.close()
            except Exception: pass
    return "; ".join(out)+f"  holders[{_who443()}]"

def _las_up():
    # Use CONNECT, never bind: a bind probe momentarily seizes 127.0.0.1:443 and can
    # race Stinky's own LAS bind, blocking the service from ever coming up.
    import socket
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(0.6)
    try: s.connect(('127.0.0.1',443)); return True
    except Exception: return False
    finally:
        try: s.close()
        except Exception: pass

def _diag_env():
    import platform
    try:
        v=sys.getwindowsversion(); winver=f"{v.major}.{v.minor}.{v.build}"
    except Exception: winver='?'
    try: admin=bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception: admin='?'
    diag("================= RUN START =================")
    diag(f"win={winver} arch={platform.machine()} admin={admin} frozen={getattr(sys,'frozen',False)} py={sys.version.split()[0]}")
    diag(f"exe={sys.executable}")
    diag(f"BASE={BASE} cwd={os.getcwd()}")
    diag(f"STINKY={STINKY}")
    for f in ['kw_rva.txt','license.txt','capture_my_priv.bin','cap_nonce_b64.txt','cap_rid_b64.txt','capture_response.json','mock_cert.pem','mock_key.pem']:
        p=os.path.join(BASE,f)
        diag(f"  file {f}: {'ok('+str(os.path.getsize(p))+'B)' if os.path.exists(p) else 'MISSING <<<'}")
    sd=os.path.join(BASE,'stlinky')
    try: diag(f"  stlinky/: {os.listdir(sd)}")
    except Exception as e: diag(f"  stlinky/: MISSING <<< ({e!r})")
    try: diag(f"  stlinky/archive/: {os.listdir(os.path.join(sd,'archive'))}")
    except Exception as e: diag(f"  stlinky/archive/: MISSING <<< Stinky needs this ({e!r})")
    diag(f"port443 (before start): {_port443()}")

def main():
    global IS_MAIN
    IS_MAIN = True
    if not STINKY: diag("FATAL: Stinky.exe not found in stlinky\\"); return 1
    _diag_env()
    hard_reset(); print("[reset] cleared leftover monitor / Stinky / port 443 from previous runs")
    try:
        if getattr(sys, 'frozen', False):
            tr = f'"{sys.executable}" --monitor'
        else:
            tr = f'"{sys.executable}" "{os.path.join(BASE,"monitor.py")}"'
        # /rl highest so the watchdog can OpenProcess a game that the user launched
        # elevated (an elevated MC launcher is common); an elevated monitor can still
        # open a non-elevated game too, so highest is the robust choice for everyone.
        subprocess.run(['schtasks','/create','/tn','StinkyMon','/tr',tr,'/sc','once','/st','00:00','/rl','highest','/f'],
                       capture_output=True)
        subprocess.run(['schtasks','/run','/tn','StinkyMon'], capture_output=True)
        print("[monitor] launched via schtasks (independent of this window)")
    except Exception as e:
        print(f"[monitor] failed to launch monitor: {e!r}")
    subprocess.run(['powershell','-NoProfile','-Command',"Get-Process Stinky -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue; Get-NetTCPConnection -LocalPort 443 -State Listen -EA SilentlyContinue | ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -EA SilentlyContinue }"],capture_output=True)
    time.sleep(1)
    # Set the clock to Aug-25 so ALL of Stinky's time sources (hooked + unhooked KUSER/QPC/tick)
    # agree -> Stinky's LAS stays alive. Captured now; restored to real time in cleanup().
    state['orig_time']=get_system_time(); state['mono0']=time.monotonic()
    print(f"Original system time: {state['orig_time']}")
    set_system_time(TARGET_TIME); diag(f"system clock set to {TARGET_TIME} (restored on exit)")
    state['U0']=get_unix()
    print("Stinky Offline")
    print("real time:", time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime(state['U0'])))
    try: hosts_add(); ok = any('slinky' in l.lower() for l in open(HOSTS,encoding='utf-8',errors='replace')); diag(f"hosts_add done, api.slinky.gg mapped={ok}")
    except Exception as e: diag(f"hosts_add FAILED {e!r} (hosts not writable? AV locking it?)")
    try: cert_install(); diag("cert_install done (certutil ROOT)")
    except Exception as e: diag(f"cert_install FAILED {e!r}")
    # The mock server (api.stinky.top) is NOT run here. Stinky can resolve the owning PID of the
    # api.stinky.top TCP peer and TerminateProcess it as anti-tamper, so the mock lives inside the
    # sacrificial --debugger child (alongside the debugger). This main process then owns nothing
    # Stinky can fingerprint (no mock socket, not the debugger) and survives to print READY +
    # restore the clock on exit.
    try: os.remove(STATUS_FILE)
    except Exception: pass
    _dbgcmd = ([sys.executable,'--debugger'] if getattr(sys,'frozen',False)
               else [sys.executable, os.path.join(BASE,'stinky_offline.py'),'--debugger'])
    subprocess.Popen(_dbgcmd, cwd=BASE, creationflags=0x08000000,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    print("authorizing Stinky ... (mock + debugger run in the sacrificial child)")
    t0=time.time(); _st=None
    while time.time()-t0<90:
        try:
            if os.path.exists(STATUS_FILE):
                _st=open(STATUS_FILE,encoding='utf-8',errors='replace').read().strip()
                if _st: break
        except Exception: pass
        time.sleep(0.3)
    print()
    approved = bool(_st and _st.startswith('OK'))
    if approved:
        state['stinky_ready']=True
        try: state['stinky_pid']=int(_st.split()[1])
        except Exception: pass
    diag(f"activation(child): status={_st!r} approved={approved} stinky_pid={state.get('stinky_pid')}")
    diag(f"LAS 127.0.0.1:443 (immediate): up={_las_up()}")
    if not approved:
        diag(f"stinky stdout tail: {state['out'][-400:]!r}")
    if approved:
        print("=====================================================", flush=True)
        print(" Stinky authorized! Starting the local service...", flush=True)
        print(" DO NOT open Slinky yet -- wait for the READY message below.", flush=True)
        print(" (opening Slinky now gives 'connection refused / target machine", flush=True)
        print("  actively refused it' -- that just means the service isn't up yet)", flush=True)
        print("=====================================================", flush=True)
        # Don't make the user guess the timing: actively wait until Stinky's LAS is truly
        # listening on 127.0.0.1:443, then announce READY. This kills the whole "opened Slinky
        # too early -> connection refused" failure class that hits slower machines.
        las_ok = False
        for i in range(240):
            if _las_up():
                las_ok = True; break
            if i and i % 10 == 0:
                alive = process_exists('Stinky.exe')
                print(f"   ... local service still starting ({i}s, Stinky_running={alive})", flush=True)
                if not alive:
                    diag(f"WAIT[{i}s]: Stinky.exe NOT running while waiting for LAS <<<")
            time.sleep(1)
        if las_ok:
            diag(f"LAS confirmed UP after {i}s; port443[{_who443()}]")
            print("", flush=True)
            print("#####################################################", flush=True)
            print("#  READY! The local service is UP.", flush=True)
            print("#  1) Open Minecraft 1.8.9 (get to the main menu).", flush=True)
            print("#  2) Double-click Slinky.exe.", flush=True)
            print("#  Keep THIS window open the whole time you play.", flush=True)
            print("#####################################################", flush=True)
        else:
            alive = process_exists('Stinky.exe')
            diag(f"LAS NEVER came up in 240s <<< stinky_alive={alive} port443[{_who443()}] las_immediate={_las_up()}")
            print("", flush=True)
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", flush=True)
            print(" PROBLEM: the local service (127.0.0.1:443) did not start.", flush=True)
            print(f" Stinky still running: {alive}", flush=True)
            print(" Opening Slinky now WILL fail with 'connection refused'.", flush=True)
            print(" Please send the file  app\\diag.log  so I can fix it.", flush=True)
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", flush=True)
    else:
        print("Stinky did NOT reach 'license approved'. See diag.log for the reason.")
        print("Make sure stlinky\\archive\\ exists, then re-run.")
    if os.environ.get('STINKY_TEST'): dbglog("return STINKY_TEST"); return 0
    print("[main] entering keep-alive loop (this window must stay open)", flush=True)
    dbglog("entering keep-alive loop")
    try:
        n=0
        while True:
            time.sleep(1); n+=1
            if n<=3 or n%15==0:
                print(f"[main] alive {n}s", flush=True)
                dbglog(f"alive {n}")
    except KeyboardInterrupt:
        dbglog("KeyboardInterrupt"); print("[main] KeyboardInterrupt", flush=True)
    except Exception as e:
        dbglog(f"loop error {e!r}"); print(f"[main] loop error: {e!r}", flush=True)
    dbglog("main returning 0")
    return 0

if __name__=='__main__':
    if '--debugger' in sys.argv:
        # Sacrificial child: run the mock server (api.stinky.top) AND debug/activate Stinky, then
        # let Stinky's anti-debug kill THIS process (the debugger + fake-server owner) instead of
        # the real launcher. Reports via STATUS_FILE; os._exit skips the parent's atexit cleanup.
        threading.Thread(target=run_mock,daemon=True).start(); time.sleep(1.5)
        try: run_stinky()
        except Exception as _e:
            try: open(STATUS_FILE,'w',encoding='utf-8').write(f"FAIL exc:{_e!r}")
            except Exception: pass
        os._exit(0)
    import traceback as _traceback
    def _hook(t, v, tb):
        diag("UNCAUGHT EXCEPTION:\n" + ''.join(_traceback.format_exception(t, v, tb)))
    sys.excepthook = _hook
    try:
        threading.excepthook = lambda a: diag(f"THREAD UNCAUGHT [{getattr(a.thread,'name','?')}]: {a.exc_value!r}\n" + ''.join(_traceback.format_exception(a.exc_type, a.exc_value, a.exc_traceback)))
    except Exception: pass
    dbglog("== script start ==")
    try:
        rc=main()
    except KeyboardInterrupt:
        rc=0
    except Exception as _e:
        diag("main() CRASHED:\n" + _traceback.format_exc()); rc=1
    finally:
        cleanup()
    dbglog(f"== script end rc={rc} ==")
    sys.exit(rc if isinstance(rc,int) else 0)
