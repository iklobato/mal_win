# Malware Testing Suite

This directory contains comprehensive unit tests and integration tests for the malware payload, including tests for different encapsulation/obfuscation methods.

## Test Structure

### Core Functionality Tests

- **test_encoders.py**: Tests for all string obfuscation encoders
  - TransformEncoder (base64, XOR)
  - SplitReassembleEncoder
  - DerivedStringEncoder
  - LazyDecoder
  - MultiRepresentationEncoder
  - ControlFlowEncoder
  - ExternalizedEncoder
  - WipeableString
  - DecoyStringManager

- **test_execution_methods.py**: Tests for command execution vectors
  - WinAPI execution
  - PowerShell execution
  - WMI execution
  - os.system execution
  - Subprocess hidden execution
  - Sandbox detection
  - Timing evasion

- **test_persistence.py**: Tests for persistence mechanisms
  - Registry persistence
  - Persistence detection
  - Installation verification

### Encapsulation Tests

- **test_encapsulation.py**: Tests for different encapsulation methods
  - Base64 encoding/decoding
  - PyInstaller executables
  - Gzip compression
  - Zlib compression
  - Multi-layer obfuscation (base64 + gzip, XOR + base64, etc.)
  - Dynamic code execution methods

- **test_integration.py**: Integration tests
  - Full workflow testing
  - Base64 encapsulated execution
  - Mock C&C server integration
  - Multi-layer encapsulation execution

## Running Tests

### Run All Tests

```bash
python -m pytest tests/ -v
```

### Run Specific Test Suite

```bash
# Test encoders only
python -m pytest tests/test_encoders.py -v

# Test encapsulation methods
python -m pytest tests/test_encapsulation.py -v

# Test execution methods
python -m pytest tests/test_execution_methods.py -v
```

### Run Specific Test

```bash
python -m pytest tests/test_encoders.py::TestTransformEncoder -v
```

### Using Test Runner Script

```bash
# Run all tests
python tests/test_runner.py

# Run specific test
python tests/test_runner.py --test tests.test_encoders.TestTransformEncoder

# Verbose output
python tests/test_runner.py --verbose
```

## Testing Encapsulation Methods

### Base64 Encapsulation

The tests verify that the malware can be:
1. Encoded to base64
2. Wrapped in a decoder script
3. Executed successfully

Example test:
```python
# Encode script
encoded = base64.b64encode(script_content)

# Create wrapper
wrapper = f"import base64; exec(base64.b64decode('{encoded}'))"

# Execute and verify
```

### PyInstaller Encapsulation

Tests verify:
1. PyInstaller spec file is valid
2. Script can be imported (required for PyInstaller)
3. Build process would succeed

### Multi-Layer Encapsulation

Tests verify combinations:
- Base64 + Gzip
- XOR + Base64
- Hex + Base64
- Multiple base64 layers

## CI/CD Integration

Tests run automatically on:
- Push to main/develop branches
- Pull requests
- Manual workflow dispatch

See `.github/workflows/test.yml` for CI configuration.

## Test Coverage

Current test coverage includes:
- ✅ All encoder types
- ✅ All execution methods
- ✅ Persistence mechanisms
- ✅ Sandbox detection
- ✅ Base64 encapsulation
- ✅ Compression methods
- ✅ Multi-layer obfuscation

## Notes

- Some tests require Windows (PyInstaller, registry tests)
- Integration tests use mock servers
- Tests are designed to run in isolated environments
- No actual malicious commands are executed in tests
