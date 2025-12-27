"""
Pytest configuration and fixtures for malware testing.
"""
import sys
import os
import pytest
from unittest.mock import Mock, MagicMock, patch

# Add parent directory to path to import hansen-tcap
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the module (handle hyphen in filename)
import importlib.util
spec = importlib.util.spec_from_file_location("hansen_tcap", os.path.join(os.path.dirname(os.path.dirname(__file__)), "hansen-tcap.py"))
hansen_tcap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hansen_tcap)


@pytest.fixture
def mock_windows_apis():
    """Fixture to mock Windows API calls."""
    # Create mock windll object
    mock_windll = Mock()
    
    # Mock kernel32
    mock_kernel32 = Mock()
    mock_kernel32.GetTickCount.return_value = 120000  # Normal uptime
    mock_kernel32.CreateProcessA.return_value = True
    mock_kernel32.WaitForSingleObject.return_value = 0
    mock_kernel32.CloseHandle.return_value = True
    
    # Mock advapi32
    mock_advapi32 = Mock()
    mock_advapi32.RegOpenKeyExW.return_value = 0  # ERROR_SUCCESS
    mock_advapi32.RegQueryValueExW.return_value = 0  # ERROR_SUCCESS
    mock_advapi32.RegCreateKeyExW.return_value = 0  # ERROR_SUCCESS
    mock_advapi32.RegSetValueExW.return_value = 0  # ERROR_SUCCESS
    mock_advapi32.RegCloseKey.return_value = 0  # ERROR_SUCCESS
    
    mock_windll.kernel32 = mock_kernel32
    mock_windll.advapi32 = mock_advapi32
    
    # Patch wintypes.REGSAM and LPDWORD which don't exist on non-Windows
    from ctypes import wintypes, c_ulong
    # REGSAM is a DWORD (unsigned long) on Windows
    # LPDWORD is a pointer to DWORD, which already exists in wintypes
    # Create a proper ctypes type for REGSAM
    REGSAM = c_ulong
    
    with patch.object(hansen_tcap.ctypes, 'windll', mock_windll, create=True), \
         patch.object(hansen_tcap.wintypes, 'REGSAM', create=True, new=REGSAM):
        yield {
            'kernel32': mock_kernel32,
            'advapi32': mock_advapi32,
            'windll': mock_windll
        }


@pytest.fixture
def mock_network():
    """Fixture to mock network requests."""
    with patch('hansen_tcap.urllib.request.urlopen') as mock_urlopen:
        # Default successful response - make it a context manager
        mock_response = MagicMock()
        mock_response.read.return_value = b'{"command": "echo test"}'
        # Make it work as a context manager
        mock_urlopen.return_value = mock_response
        
        yield {
            'urlopen': mock_urlopen,
            'response': mock_response
        }


@pytest.fixture
def mock_subprocess():
    """Fixture to mock subprocess execution."""
    with patch('hansen_tcap.subprocess.run') as mock_run:
        # Default successful subprocess - create CompletedProcess-like object
        from types import SimpleNamespace
        mock_result = SimpleNamespace()
        mock_result.returncode = 0
        mock_result.stdout = b""
        mock_result.stderr = b""
        mock_run.return_value = mock_result
        
        yield {
            'run': mock_run,
            'result': mock_result
        }


@pytest.fixture
def mock_time():
    """Fixture to mock time-dependent functions."""
    with patch('hansen_tcap.time.time') as mock_time_func:
        # Start at time 0, increment by 0.1 each call
        time_values = [0.0]
        def get_time():
            current = time_values[0]
            time_values[0] += 0.1
            return current
        mock_time_func.side_effect = get_time
        
        yield mock_time_func


@pytest.fixture
def reset_error_log():
    """Fixture to clear _error_log before each test."""
    # Clear error log before test
    if hasattr(hansen_tcap, '_error_log'):
        hansen_tcap._error_log.clear()
    yield
    # Clear error log after test
    if hasattr(hansen_tcap, '_error_log'):
        hansen_tcap._error_log.clear()


@pytest.fixture
def sample_command():
    """Fixture providing sample command strings for testing."""
    return "echo test"


@pytest.fixture
def mock_random():
    """Fixture to mock random.choice for deterministic testing."""
    with patch('hansen_tcap.random.choice') as mock_choice:
        # Return first decoy command by default
        if hasattr(hansen_tcap, 'DECOY_COMMANDS') and hansen_tcap.DECOY_COMMANDS:
            mock_choice.return_value = hansen_tcap.DECOY_COMMANDS[0]
        else:
            mock_choice.return_value = 'echo "Windows Update"'
        yield mock_choice


@pytest.fixture
def mock_platform():
    """Fixture to mock platform.system() for cross-platform testing."""
    with patch('hansen_tcap.platform.system') as mock_system:
        mock_system.return_value = 'Windows'
        yield mock_system


@pytest.fixture
def mock_os_cpu_count():
    """Fixture to mock os.cpu_count() for CPU count testing."""
    with patch('hansen_tcap.os.cpu_count') as mock_cpu_count:
        mock_cpu_count.return_value = 4  # Normal CPU count
        yield mock_cpu_count
