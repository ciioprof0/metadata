# encoding_converter.py
# -*- coding: utf-8 -*-

"""
This module provides functionality to convert file encodings to UTF-8.
"""

# Import Standard Library Modules
import os
import logging

# Import Third-Party Modules
import chardet  # For detecting character encoding
# pip install chardet

class myEncodingConverter:
    """
    A class to convert file encoding from detected to UTF-8.
    """

    def __init__(self, file_path):
        """
        Initialize the EncodingConverter with the file path.
        Initialize the original encoding to None.
        """
        self.file_path = file_path
        self.orig_encode = None  # Attribute to store the original encoding

    def detect_encoding(self):
        """
        Detect the encoding of the file using chardet.
        Set the original encoding attribute with the detected encoding.
        """
        with open(self.file_path, 'rb') as file:
            rawdata = file.read()
        self.orig_encode = chardet.detect(rawdata)['encoding']  # Set the original encoding
        logging.info(f"Detected encoding: {self.orig_encode}")
        return self.orig_encode

    def convert_to_utf8(self):
        """
        Convert file to UTF-8 from the detected encoding.
        Skips conversion if the file is already in UTF-8 encoding.
        """
        if self.orig_encode is None:
            raise ValueError("Original encoding not detected yet.")

        # Skip conversion if the file is already UTF-8
        if self.orig_encode.lower() == 'utf-8':
            logging.info(f"File '{self.file_path}' is already in UTF-8 encoding. No conversion necessary.")
            return

        # Read the original file
        with open(self.file_path, 'r', encoding=self.orig_encode, errors='replace') as file:
            content = file.read()

        # Prepare the new file path
        base, extension = os.path.splitext(self.file_path)
        new_file_path = f"{base}_utf8{extension}"

        # Write the converted content to the new file
        with open(new_file_path, 'w', encoding='utf-8') as file:
            file.write(content)
        logging.info(f"File converted and saved to {new_file_path}")

    @staticmethod
    def convert(file_path):
        """
        Static method to detect and convert file encoding to UTF-8.
        """
        converter = myEncodingConverter(file_path)
        converter.detect_encoding()
        converter.convert_to_utf8()
        return f"{os.path.splitext(file_path)[0]}_utf8{os.path.splitext(file_path)[1]}"

# Main
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

    # Convert file encoding to UTF-8
    file_path = 'test_files/utf8.txt' # Replace with your file path
    new_file_path = myEncodingConverter.convert(file_path)
    print(f"Converted file saved to {new_file_path}")


# References
"""
Coding assistance from:
GitHub. (2023). Copilot Extension for VSCode [Computer software]. https://github.com/features/copilot

OpenAI. (2023). ChatGPT 4 (Nov 6 version) [Large language model]. https://chat.openai.com/share/{chat_id}

"""