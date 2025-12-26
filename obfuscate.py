#!/usr/bin/env python3
import re
import sys
import random
import string
import os

def generate_random_name(length=12):
    chars = string.ascii_lowercase + string.digits
    return ''.join(random.choices(chars, k=length))

def obfuscate_strings(content):
    string_pattern = r'"([^"\\]*(\\.[^"\\]*)*)"'
    string_map = {}
    counter = 0
    
    def replace_func(match):
        nonlocal counter
        original_str = match.group(0)
        if original_str in string_map:
            var_name = string_map[original_str]
        else:
            var_name = f'_str_{counter}'
            string_map[original_str] = var_name
            counter += 1
        return var_name
    
    new_content = re.sub(string_pattern, replace_func, content)
    
    declarations = []
    for orig, var_name in string_map.items():
        declarations.append(f'static const char {var_name}[] = {orig};')
    
    if declarations:
        insert_pos = content.find('typedef enum')
        if insert_pos == -1:
            insert_pos = content.find('#define')
        if insert_pos != -1:
            new_content = new_content[:insert_pos] + '\n'.join(declarations) + '\n' + new_content[insert_pos:]
    
    return new_content

def obfuscate_identifiers(content):
    identifier_pattern = r'\b([a-z_][a-z0-9_]{3,})\b'
    
    keywords = {
        'if', 'else', 'for', 'while', 'return', 'int', 'char', 'void', 
        'static', 'const', 'struct', 'typedef', 'enum', 'sizeof', 'NULL',
        'TRUE', 'FALSE', 'BOOL', 'DWORD', 'LONG', 'HKEY', 'CURL', 'size_t',
        'printf', 'fprintf', 'sprintf', 'snprintf', 'strlen', 'strcmp', 
        'strcpy', 'strncpy', 'memset', 'memcpy', 'malloc', 'free', 
        'atoi', 'fopen', 'fclose', 'fread', 'fwrite', 'main', 'include',
        'define', 'pragma', 'ifdef', 'endif', 'extern', 'volatile', 'register'
    }
    
    identifiers = set()
    matches = re.finditer(identifier_pattern, content, re.IGNORECASE)
    for match in matches:
        ident = match.group(1)
        if ident.lower() not in keywords and len(ident) > 3:
            identifiers.add(ident)
    
    id_map = {}
    for ident in sorted(identifiers, key=len, reverse=True):
        if ident not in id_map:
            id_map[ident] = f'_{generate_random_name()}'
    
    for old, new in id_map.items():
        content = re.sub(r'\b' + re.escape(old) + r'\b', new, content)
    
    return content

def add_control_flow_obfuscation(content):
    lines = content.split('\n')
    result = []
    indent_level = 0
    
    for line in lines:
        stripped = line.lstrip()
        current_indent = len(line) - len(stripped)
        
        if '{' in line:
            indent_level += 1
        if '}' in line:
            indent_level -= 1
        
        result.append(line)
        
        if random.random() < 0.15 and ';' in line and '{' not in line and '}' not in line:
            junk_id = generate_random_name(6)
            junk_code = ' ' * (current_indent + 4) + f'volatile int _{junk_id} = {random.randint(0, 1000)};'
            result.append(junk_code)
            junk_code2 = ' ' * (current_indent + 4) + f'if (_{junk_id} > 0) {{ _{junk_id}++; }}'
            result.append(junk_code2)
    
    return '\n'.join(result)

def add_dummy_functions(content):
    dummy_funcs = []
    for i in range(3):
        func_name = f'_{generate_random_name()}'
        dummy_funcs.append(f'''
static void {func_name}(void) {{
    volatile int _{generate_random_name(4)} = {random.randint(1, 100)};
    volatile char _{generate_random_name(4)}[16];
    memset(_{generate_random_name(4)}, 0, 16);
}}
''')
    
    insert_pos = content.find('static result_code_t')
    if insert_pos != -1:
        content = content[:insert_pos] + '\n'.join(dummy_funcs) + '\n' + content[insert_pos:]
    
    return content

def obfuscate_file(input_file, output_file):
    print(f"Reading {input_file}...")
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    print("Obfuscating strings...")
    content = obfuscate_strings(content)
    
    print("Obfuscating identifiers...")
    content = obfuscate_identifiers(content)
    
    print("Adding control flow obfuscation...")
    content = add_control_flow_obfuscation(content)
    
    print("Adding dummy functions...")
    content = add_dummy_functions(content)
    
    print(f"Writing obfuscated code to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    original_size = os.path.getsize(input_file)
    obfuscated_size = os.path.getsize(output_file)
    print(f"Obfuscation complete!")
    print(f"Original size: {original_size} bytes")
    print(f"Obfuscated size: {obfuscated_size} bytes")
    print(f"Size increase: {obfuscated_size - original_size} bytes ({((obfuscated_size - original_size) / original_size * 100):.1f}%)")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python obfuscate.py <input.c> <output.c>")
        sys.exit(1)
    
    random.seed()
    obfuscate_file(sys.argv[1], sys.argv[2])
