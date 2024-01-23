#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import locale
import platform
import os
import subprocess
import sys

def get_system_info():
    locale.setlocale(locale.LC_ALL, '')
    info = {
        "    Operating System": platform.system(),
        "    OS Version": platform.version(),
        "    OS Release": platform.release(),
        "    Locale": locale.getlocale(),
        "    LANG Environment": os.getenv('LANG'),
        "    LANGUAGE Environment": os.getenv('LANGUAGE'),
        "    LC_ALL Environment": os.getenv('LC_ALL'),
        "    LC_CTYPE Environment": os.getenv('LC_CTYPE')
    }
    return info

def get_terminal_info():
    shell = os.getenv('SHELL', 'Not Detected')
    terminal = os.getenv('TERM', 'Not Detected')
    encoding_info = {}

    if platform.system() == "Windows":
        shell = os.getenv('COMSPEC', 'Not Detected')
        try:
            cp_output = subprocess.check_output("chcp", shell=True).decode()
            encoding_info['Windows Code Page'] = cp_output.strip()
        except Exception as e:
            encoding_info['Windows Code Page'] = f"Error detecting code page: {e}"

    else:
        encoding_info = {
            "LANG Environment": os.getenv('LANG', 'Not Set'),
            "LC_ALL Environment": os.getenv('LC_ALL', 'Not Set'),
            "LC_CTYPE Environment": os.getenv('LC_CTYPE', 'Not Set')
        }

    info = {
        "    Terminal": terminal,
        "    Shell": shell,
        "    Encoding Info": encoding_info
    }
    return info


def get_python_info():
    info = {
        "    Python Version": platform.python_version(),
        "    Default Encoding": sys.getdefaultencoding(),
        "    File System Encoding": sys.getfilesystemencoding(),
        "    Standard Input Encoding": sys.stdin.encoding,
        "    Standard Output Encoding": sys.stdout.encoding
    }
    return info

# Display system information
system_info = get_system_info()
terminal_info = get_terminal_info()
python_info = get_python_info()

print("System Information:")
for key, value in system_info.items():
    print(f"{key}: {value}")

print("\nTerminal and Shell Information:")
for key, value in terminal_info.items():
    if isinstance(value, dict):
        print(f"{key}:")
        for subkey, subvalue in value.items():
            print(f"    {subkey}: {subvalue}")
    else:
        print(f"{key}: {value}")

print("\nPython Environment Information:")
for key, value in python_info.items():
    print(f"{key}: {value}")

print("\n")


# References
"""
Coding assistance from:
GitHub. (2023). Copilot Extension for VSCode [Computer software]. https://github.com/features/copilot

OpenAI. (2023). ChatGPT 4 (Nov 6 version) [Large language model]. https://chat.openai.com/share/{chat_id}

"""