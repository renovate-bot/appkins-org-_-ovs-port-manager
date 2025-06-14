#!/usr/bin/env python3
import re

def convert_withfields_to_logr(text):
    # Pattern to match WithFields patterns
    pattern = r'm\.logger\.V\((\d+)\)\.WithFields\(logrus\.Fields\{\s*((?:[^}]*\n?)*?)\s*\}\)\.(\w+)\(([^)]*)\)'
    
    def replace_withfields(match):
        verbosity = match.group(1)
        fields_content = match.group(2)
        log_level = match.group(3)
        message = match.group(4)
        
        # Parse the fields
        field_pairs = []
        for line in fields_content.split('\n'):
            line = line.strip()
            if ':' in line and line.endswith(','):
                line = line.rstrip(',')
                key, value = line.split(':', 1)
                key = key.strip().strip('"')
                value = value.strip()
                field_pairs.append(f'"{key}", {value}')
        
        # Convert log level
        if log_level in ['Debug', 'Info']:
            new_level = 'Info'
            v_level = '2' if log_level == 'Debug' else '1'
        elif log_level in ['Warn', 'Error']:
            new_level = 'Error'
            v_level = '1'
        else:
            new_level = 'Info'
            v_level = '1'
        
        # Build the new log call
        if log_level in ['Warn', 'Error']:
            fields_str = ', '.join(field_pairs)
            return f'm.logger.V({v_level}).{new_level}(nil, {message}, {fields_str})'
        else:
            fields_str = ', '.join(field_pairs)
            return f'm.logger.V({v_level}).{new_level}({message}, {fields_str})'
    
    return re.sub(pattern, replace_withfields, text, flags=re.MULTILINE | re.DOTALL)

if __name__ == "__main__":
    with open('internal/manager/manager.go', 'r') as f:
        content = f.read()
    
    converted = convert_withfields_to_logr(content)
    
    with open('internal/manager/manager.go', 'w') as f:
        f.write(converted)
    
    print("Converted WithFields patterns")
