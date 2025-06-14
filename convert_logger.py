#!/usr/bin/env python3
import re
import sys

def convert_logrus_to_logr(content):
    # Replace simple WithField patterns
    content = re.sub(
        r'm\.logger\.V\((\d+)\)\.WithField\("([^"]+)", ([^)]+)\)\.Info\("([^"]+)"\)',
        r'm.logger.V(\1).Info("\4", "\2", \3)',
        content
    )
    
    content = re.sub(
        r'm\.logger\.V\((\d+)\)\.WithField\("([^"]+)", ([^)]+)\)\.Debug\("([^"]+)"\)',
        r'm.logger.V(\1).Info("\4", "\2", \3)',
        content
    )
    
    content = re.sub(
        r'm\.logger\.V\((\d+)\)\.WithField\("([^"]+)", ([^)]+)\)\.Warn\("([^"]+)"\)',
        r'm.logger.V(\1).Error(nil, "\4", "\2", \3)',
        content
    )
    
    # Replace WithError patterns
    content = re.sub(
        r'm\.logger\.V\((\d+)\)\.WithError\(([^)]+)\)\.Error\("([^"]+)"\)',
        r'm.logger.Error(\2, "\3")',
        content
    )
    
    content = re.sub(
        r'm\.logger\.V\((\d+)\)\.WithError\(([^)]+)\)\.WithField\("([^"]+)", ([^)]+)\)\.Error\("([^"]+)"\)',
        r'm.logger.Error(\2, "\5", "\3", \4)',
        content
    )
    
    content = re.sub(
        r'm\.logger\.V\((\d+)\)\.WithError\(([^)]+)\)\.WithField\("([^"]+)", ([^)]+)\)\.Warn\("([^"]+)"\)',
        r'm.logger.V(\1).Error(\2, "\5", "\3", \4)',
        content
    )
    
    content = re.sub(
        r'm\.logger\.V\((\d+)\)\.WithError\(([^)]+)\)\.Debug\("([^"]+)"\)',
        r'm.logger.V(\1).Error(\2, "\3")',
        content
    )
    
    return content

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 convert_logger.py <file>")
        sys.exit(1)
    
    filename = sys.argv[1]
    with open(filename, 'r') as f:
        content = f.read()
    
    converted = convert_logrus_to_logr(content)
    
    with open(filename, 'w') as f:
        f.write(converted)
    
    print(f"Converted {filename}")
