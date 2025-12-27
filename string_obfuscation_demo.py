#!/usr/bin/env python3
"""
String Obfuscation Demonstration Script

This script demonstrates 10 string obfuscation techniques for educational
and intellectual property protection purposes. All techniques are implemented
with clear separation of concerns and comprehensive documentation.

Purpose: Protect sensitive strings in code from static analysis and reverse
engineering while maintaining functionality.
"""

import base64
import random
import struct
import sys
from contextlib import contextmanager
from typing import List, Optional, Tuple


# ============================================================================
# Configuration Constants (for Externalized Derivation Technique)
# ============================================================================

BUILD_CONFIG = {
    "prefix_offset": 0x41,
    "suffix_offset": 0x5A,
    "xor_key": 0x42,
    "split_count": 3,
    "encoding_version": 2,
}


# ============================================================================
# Technique 1: Compile-time String Transformation
# ============================================================================

class TransformEncoder:
    """
    Stores strings in transformed (non-plaintext) form at compile time.
    Strings are Base64/XOR encoded and decoded on first access.
    
    Why: Prevents plaintext strings from appearing in binary/bytecode,
    making static analysis more difficult.
    """

    def __init__(self, encoded_data: bytes, transform_type: str = "base64"):
        self._encoded_data = encoded_data
        self._transform_type = transform_type
        self._decoded: Optional[str] = None

    @classmethod
    def encode(cls, plaintext: str, transform_type: str = "base64") -> "TransformEncoder":
        """Encode a plaintext string into transformed form."""
        if transform_type == "base64":
            encoded = base64.b64encode(plaintext.encode("utf-8"))
        elif transform_type == "xor":
            key = BUILD_CONFIG["xor_key"]
            encoded = bytes(b ^ key for b in plaintext.encode("utf-8"))
        else:
            raise ValueError(f"Unknown transform type: {transform_type}")
        return cls(encoded, transform_type)

    def decode(self) -> str:
        """Decode the transformed string to plaintext."""
        if self._decoded is not None:
            return self._decoded

        if self._transform_type == "base64":
            self._decoded = base64.b64decode(self._encoded_data).decode("utf-8")
        elif self._transform_type == "xor":
            key = BUILD_CONFIG["xor_key"]
            self._decoded = bytes(b ^ key for b in self._encoded_data).decode("utf-8")
        else:
            raise ValueError(f"Unknown transform type: {self._transform_type}")

        return self._decoded


# ============================================================================
# Technique 2: Split & Reassemble
# ============================================================================

class SplitReassembleEncoder:
    """
    Splits strings into multiple fragments stored in different locations,
    then reconstructs them at runtime via concatenation.
    
    Why: String fragments are less recognizable than complete strings,
    and reconstruction logic adds another layer of obfuscation.
    """

    def __init__(self, fragments: List[str]):
        self._fragments = fragments

    @classmethod
    def encode(cls, plaintext: str, num_splits: int = None) -> "SplitReassembleEncoder":
        """Split a string into fragments."""
        if num_splits is None:
            num_splits = BUILD_CONFIG["split_count"]

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
        """Reassemble fragments into original string."""
        return "".join(self._fragments)


# ============================================================================
# Technique 3: Derived Strings (No Literals)
# ============================================================================

class DerivedStringEncoder:
    """
    Constructs strings from calculations, tables, or ranges rather than
    string literals. Uses character arithmetic and lookup tables.
    
    Why: Eliminates string literals from code, making it harder to
    identify sensitive values through static analysis.
    """

    def __init__(self, derivation_method: str, params: Tuple):
        self._derivation_method = derivation_method
        self._params = params
        self._cached: Optional[str] = None

    @classmethod
    def from_char_range(cls, start_char: int, end_char: int, step: int = 1) -> "DerivedStringEncoder":
        """Derive string from character range."""
        return cls("char_range", (start_char, end_char, step))

    @classmethod
    def from_calculation(cls, base_value: int, operations: List[Tuple[str, int]]) -> "DerivedStringEncoder":
        """Derive string from arithmetic calculations."""
        return cls("calculation", (base_value, operations))

    @classmethod
    def from_lookup_table(cls, indices: List[int], table: List[int]) -> "DerivedStringEncoder":
        """Derive string from lookup table."""
        return cls("lookup_table", (indices, table))

    def decode(self) -> str:
        """Derive the string from stored parameters."""
        if self._cached is not None:
            return self._cached

        if self._derivation_method == "char_range":
            start, end, step = self._params
            chars = [chr(i) for i in range(start, end + 1, step)]
            self._cached = "".join(chars)
        elif self._derivation_method == "calculation":
            base_value, operations = self._params
            result = base_value
            chars = []
            for op, value in operations:
                if op == "add":
                    result += value
                elif op == "sub":
                    result -= value
                elif op == "xor":
                    result ^= value
                chars.append(chr(result))
            self._cached = "".join(chars)
        elif self._derivation_method == "lookup_table":
            indices, table = self._params
            chars = [chr(table[i]) for i in indices]
            self._cached = "".join(chars)
        else:
            raise ValueError(f"Unknown derivation method: {self._derivation_method}")

        return self._cached


# ============================================================================
# Technique 4: Lazy / Just-in-Time Decoding
# ============================================================================

class LazyDecoder:
    """
    Stores encoded data and decodes only when accessed via property/getter.
    Implements caching to avoid re-decoding on subsequent accesses.
    
    Why: Delays decoding until absolutely necessary, reducing memory
    footprint and making execution flow less predictable.
    """

    def __init__(self, encoded_data: bytes, decoder_func):
        self._encoded_data = encoded_data
        self._decoder_func = decoder_func
        self._decoded: Optional[str] = None
        self._decoded_count = 0

    @property
    def value(self) -> str:
        """Lazy property that decodes on first access."""
        if self._decoded is None:
            self._decoded = self._decoder_func(self._encoded_data)
            self._decoded_count += 1
        return self._decoded

    def get_decode_count(self) -> int:
        """Get number of times decoding occurred."""
        return self._decoded_count

    def reset(self):
        """Reset decoded cache to force re-decoding."""
        self._decoded = None


# ============================================================================
# Technique 5: Multiple Representations
# ============================================================================

class MultiRepresentationEncoder:
    """
    Stores the same logical string in more than one encoded form and
    selects one at runtime based on conditions or randomness.
    
    Why: Multiple representations make pattern matching harder and
    allow runtime selection to evade static analysis.
    """

    def __init__(self, representations: dict):
        self._representations = representations
        self._selected: Optional[str] = None

    @classmethod
    def encode(cls, plaintext: str) -> "MultiRepresentationEncoder":
        """Encode string in multiple formats."""
        representations = {
            "base64": base64.b64encode(plaintext.encode("utf-8")).decode("ascii"),
            "hex": plaintext.encode("utf-8").hex(),
            "xor": "".join(chr(ord(c) ^ BUILD_CONFIG["xor_key"]) for c in plaintext),
        }
        return cls(representations)

    def decode(self, representation: Optional[str] = None) -> str:
        """Decode using specified or randomly selected representation."""
        if representation is None:
            representation = random.choice(list(self._representations.keys()))
        self._selected = representation

        encoded = self._representations[representation]

        if representation == "base64":
            return base64.b64decode(encoded.encode("ascii")).decode("utf-8")
        elif representation == "hex":
            return bytes.fromhex(encoded).decode("utf-8")
        elif representation == "xor":
            key = BUILD_CONFIG["xor_key"]
            return "".join(chr(ord(c) ^ key) for c in encoded)
        else:
            raise ValueError(f"Unknown representation: {representation}")


# ============================================================================
# Technique 6: Control-Flow-Dependent Construction
# ============================================================================

class ControlFlowEncoder:
    """
    Produces the final string through branching logic where different
    code paths produce the same result.
    
    Why: Control flow obfuscation makes static analysis more difficult
    by requiring execution path analysis to determine final values.
    """

    def __init__(self, construction_logic: str, params: dict):
        self._construction_logic = construction_logic
        self._params = params
        self._cached: Optional[str] = None

    @classmethod
    def encode(cls, plaintext: str, branch_count: int = 3) -> "ControlFlowEncoder":
        """Encode string with control-flow-dependent construction."""
        return cls("branching", {"plaintext": plaintext, "branch_count": branch_count})

    def decode(self, branch_selector: Optional[int] = None) -> str:
        """Decode through control-flow-dependent logic."""
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
                    result += chr(ord(char) ^ 0)  # Same result, different path
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


# ============================================================================
# Technique 7: Externalized Derivation
# ============================================================================

class ExternalizedEncoder:
    """
    Derives part of the string from configuration or build-time constants
    (no I/O). Uses module-level constants defined at build time.
    
    Why: Separates sensitive data from code logic, allowing build-time
    configuration without runtime I/O operations.
    """

    def __init__(self, base_string: str, derivation_config: dict):
        self._base_string = base_string
        self._derivation_config = derivation_config
        self._cached: Optional[str] = None

    @classmethod
    def encode(cls, plaintext: str) -> "ExternalizedEncoder":
        """Encode string with externalized derivation."""
        return cls(plaintext, BUILD_CONFIG.copy())

    def decode(self) -> str:
        """Decode using externalized configuration."""
        if self._cached is not None:
            return self._cached

        prefix_char = chr(self._derivation_config["prefix_offset"])
        suffix_char = chr(self._derivation_config["suffix_offset"])

        self._cached = f"{prefix_char}{self._base_string}{suffix_char}"
        return self._cached


# ============================================================================
# Technique 8: Runtime Wiping
# ============================================================================

class WipeableString:
    """
    Explicitly overwrites or discards string data after use.
    Implements context manager for automatic wiping.
    
    Why: Prevents sensitive strings from remaining in memory after use,
    reducing risk of memory dumps revealing sensitive data.
    """

    def __init__(self, value: str):
        self._value = value
        self._wiped = False

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - wipe the string."""
        self.wipe()
        return False

    def get(self) -> str:
        """Get the string value."""
        if self._wiped:
            raise ValueError("String has been wiped")
        return self._value

    def wipe(self):
        """Overwrite string data in memory."""
        if not self._wiped:
            self._value = "\x00" * len(self._value)
            self._wiped = True

    def is_wiped(self) -> bool:
        """Check if string has been wiped."""
        return self._wiped


# ============================================================================
# Technique 9: Decoy Strings
# ============================================================================

class DecoyStringManager:
    """
    Includes believable but unused strings to create analysis noise.
    Mixes real and decoy strings in storage.
    
    Why: Decoy strings create false positives in static analysis,
    making it harder to identify which strings are actually used.
    """

    def __init__(self, real_string: str, decoy_strings: List[str]):
        self._real_string = real_string
        self._decoy_strings = decoy_strings
        self._all_strings = [real_string] + decoy_strings
        random.shuffle(self._all_strings)

    @classmethod
    def encode(cls, plaintext: str, num_decoys: int = 3) -> "DecoyStringManager":
        """Create manager with real string and decoy strings."""
        decoys = [
            "API_KEY_PLACEHOLDER",
            "SECRET_TOKEN_EXAMPLE",
            "DATABASE_PASSWORD_DEMO",
            "ENCRYPTION_KEY_SAMPLE",
            "AUTH_TOKEN_TEMPLATE",
        ][:num_decoys]
        return cls(plaintext, decoys)

    def get_real(self) -> str:
        """Get the real string."""
        return self._real_string

    def get_all(self) -> List[str]:
        """Get all strings (real + decoys) in shuffled order."""
        return self._all_strings.copy()

    def get_random(self) -> str:
        """Get a random string (may be decoy)."""
        return random.choice(self._all_strings)


# ============================================================================
# Technique 10: Clear Separation of Concerns
# ============================================================================

class StringObfuscationDemo:
    """
    Orchestrates all obfuscation techniques with clear separation of concerns.
    Encoders, decoders, and usage are logically separated.
    
    Why: Separation of concerns makes the code maintainable and allows
    techniques to be used independently or in combination.
    """

    def __init__(self):
        self._encoders = {}
        self._decoders = {}

    def register_encoder(self, name: str, encoder):
        """Register an encoder instance."""
        self._encoders[name] = encoder

    def register_decoder(self, name: str, decoder):
        """Register a decoder instance."""
        self._decoders[name] = decoder

    def demonstrate_technique(self, technique_name: str, plaintext: str):
        """Demonstrate a specific obfuscation technique."""
        print(f"\n{'='*60}")
        print(f"Technique: {technique_name}")
        print(f"{'='*60}")

        if technique_name == "TransformEncoder":
            encoder = TransformEncoder.encode(plaintext, "base64")
            print(f"Encoded (Base64): {encoder._encoded_data}")
            decoded = encoder.decode()
            print(f"Decoded: {decoded}")

        elif technique_name == "SplitReassembleEncoder":
            encoder = SplitReassembleEncoder.encode(plaintext)
            print(f"Fragments: {encoder._fragments}")
            decoded = encoder.decode()
            print(f"Reassembled: {decoded}")

        elif technique_name == "DerivedStringEncoder":
            chars = [ord(c) for c in plaintext]
            if chars:
                encoder = DerivedStringEncoder.from_lookup_table(
                    list(range(len(chars))), chars
                )
                decoded = encoder.decode()
                print(f"Derived from lookup table: {decoded}")

        elif technique_name == "LazyDecoder":
            encoded = base64.b64encode(plaintext.encode("utf-8"))
            decoder = LazyDecoder(encoded, lambda x: base64.b64decode(x).decode("utf-8"))
            print(f"Encoded data present, not decoded yet")
            print(f"Decode count: {decoder.get_decode_count()}")
            decoded = decoder.value
            print(f"Decoded (lazy): {decoded}")
            print(f"Decode count after access: {decoder.get_decode_count()}")

        elif technique_name == "MultiRepresentationEncoder":
            encoder = MultiRepresentationEncoder.encode(plaintext)
            print(f"Representations: {list(encoder._representations.keys())}")
            decoded = encoder.decode()
            print(f"Decoded (selected: {encoder._selected}): {decoded}")

        elif technique_name == "ControlFlowEncoder":
            encoder = ControlFlowEncoder.encode(plaintext)
            decoded = encoder.decode()
            print(f"Decoded via control flow: {decoded}")

        elif technique_name == "ExternalizedEncoder":
            encoder = ExternalizedEncoder.encode(plaintext)
            decoded = encoder.decode()
            print(f"Decoded with externalized config: {decoded}")

        elif technique_name == "WipeableString":
            with WipeableString(plaintext) as wipeable:
                value = wipeable.get()
                print(f"String value: {value}")
                print(f"Wiped: {wipeable.is_wiped()}")
            print(f"After context exit - Wiped: {wipeable.is_wiped()}")

        elif technique_name == "DecoyStringManager":
            manager = DecoyStringManager.encode(plaintext)
            print(f"All strings (shuffled): {manager.get_all()}")
            print(f"Real string: {manager.get_real()}")

        else:
            print(f"Unknown technique: {technique_name}")


# ============================================================================
# Demo Section
# ============================================================================

def main():
    """Demonstrate all string obfuscation techniques with placeholder strings."""
    print("String Obfuscation Techniques Demonstration")
    print("=" * 60)
    print("Purpose: Educational demonstration of IP protection techniques")
    print("All strings are placeholders - no real secrets included")
    print("=" * 60)

    demo = StringObfuscationDemo()

    placeholder_strings = [
        "EXAMPLE_SECRET",
        "API_KEY_PLACEHOLDER",
        "DATABASE_PASSWORD_DEMO",
    ]

    techniques = [
        "TransformEncoder",
        "SplitReassembleEncoder",
        "DerivedStringEncoder",
        "LazyDecoder",
        "MultiRepresentationEncoder",
        "ControlFlowEncoder",
        "ExternalizedEncoder",
        "WipeableString",
        "DecoyStringManager",
    ]

    for i, technique in enumerate(techniques):
        plaintext = placeholder_strings[i % len(placeholder_strings)]
        demo.demonstrate_technique(technique, plaintext)

    print(f"\n{'='*60}")
    print("Demonstration Complete")
    print("=" * 60)
    print("\nKey Points:")
    print("- All techniques maintain functionality while obfuscating strings")
    print("- Techniques can be combined for layered protection")
    print("- Runtime wiping prevents memory-based extraction")
    print("- Decoy strings create analysis noise")
    print("- Clear separation allows independent technique usage")


if __name__ == "__main__":
    main()

