#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import codecs  # Codec registry and base classes
import os  # Miscellaneous operating system interfaces

#from chardet import detect
# pip install chardet

#from cchardet import detect
# pip install faust-cchardet

from charset_normalizer import detect
# pip install charset-normalizer

# Path to the original CSV file and the output file
# Replace with your own file paths
input_file_path = r"D:/Code/data/news/FAKENEWS_05.csv"
output_file_path = r"D:/Code/data/news/FAKENEWS_05_BOM.csv"
size_to_read = 100000

# Check if the input file exists
if not os.path.exists(input_file_path):
    print(f"Error: The file {input_file_path} does not exist.")
else:
    try:
        # Detect the encoding of the original file
        with open(input_file_path, 'rb') as file:
            detected = detect(file.read(size_to_read))['encoding']  # Read a sample for efficiency
        if not isinstance(detected, str):
            detected = 'utf-8'  # Use a default encoding if detection failed

        # Read the original file
        with open(input_file_path, 'r', encoding=detected) as file:
            content = file.read()

        # Write the content to a new file with a BOM
        with codecs.open(output_file_path, 'w', encoding='utf-8-sig') as output_file:
            output_file.write(content)

        print(f"File conversion completed successfully. Output file: {output_file_path}")

    except Exception as e:
        print(f"An error occurred: {e}")


# References
"""
Coding assistance from:
GitHub. (2023). Copilot Extension for VSCode [Computer software]. https://github.com/features/copilot

OpenAI. (2023). ChatGPT 4 (Nov 6 version) [Large language model]. https://chat.openai.com/share/{chat_id}

"""