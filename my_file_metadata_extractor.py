#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
This module provides functionality for extracting and reporting metadata from
data files. It is designed to assist in the preliminary analysis of data files
of unknown origin, particularly focusing on text and numerical data files as an
early step for forensic analysis.
"""

# Import Standard Library Modules
import argparse  # For parsing command line arguments
import hashlib  # For calculating file hashes
import mimetypes  # To determine file MIME type
import platform  # For getting the operating system name
import os  # To handle basic file operations
import stat  # For getting file permissions
import time  # To handle time-related operations
from datetime import datetime, timezone # For working with timestamps

# Import Third-Party Modules
import charset_normalizer as chardet  # For detecting character encoding
# pip install charset-normalizer
import langdetect # For detecting natural language
# pip install langdetect
import magic  # For file type identification
# pip install python-magic

# Set Global Variables

# Define Script Classes
class FileMetadataExtractor:
    """
    A class for extracting and reporting metadata from a given file.

    Attributes:
        file_path (str): Path of the file to extract metadata from.
        file_stat (os.stat_result): Metadata information from the os.stat call.
        op_sys (str): Name of the operating system.
        raw_data (bytes): Raw data read from the file.
    """

    def __init__(self, file_path):
        """
        Initializes the FileMetadataExtractor with the given file path.

        Args:
            file_path (str): Path to the file for metadata extraction.
        """
        self.file_path = file_path
        self.file_stat = os.stat(file_path)
        self.op_sys = platform.system()
        self.raw_data = None
        # Initialize other necessary variables

    # Local method to calculate elapsed time between two timestamps.
    def _calculate_elapsed_time(self, time_utc, current_time_utc=datetime.now(timezone.utc)):
        """
        Calculates the elapsed time from the given timestamp to the current time.

        Args:
            time_utc (datetime): The starting time in UTC.
            current_time_utc (datetime, optional): The ending time in UTC. Defaults to current UTC time.

        Returns:
            str: Formatted elapsed time.
        """
        elapsed = current_time_utc - time_utc
        years, remainder = divmod(elapsed.total_seconds(), 31536000)
        months, remainder = divmod(remainder, 2592000)
        days, remainder = divmod(remainder, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)

        return (f"{int(years)}/{int(months)}/{int(days)}, "
                f"{int(hours)}:{int(minutes):02d}:{int(seconds):02d}")

    # Local method to check if the file is compressed.
    def _check_compression(self):
        """
        Checks if the file is in a known compressed format.

        Returns:
            bool: True if the file is compressed, False otherwise.
        """
        compression_formats = {
            '.zip': 'application/zip',
            '.gz': 'application/gzip',
            '.bz2': 'application/x-bzip2',
            '.tar': 'application/x-tar',
        }
        file_extension = os.path.splitext(self.file_path)[1].lower()
        return file_extension in compression_formats

    # Local method to format a timestamp for display.
    def _format_timestamp(self, timestamp, current_time_utc):
        """
        Formats a given timestamp and calculates the elapsed time from it.

        Args:
            timestamp (float): The Unix timestamp to format.
            current_time_utc (datetime): Current time for elapsed time calculation.

        Returns:
            str: Formatted timestamp with elapsed time.
        """
        time_utc = datetime.fromtimestamp(timestamp, timezone.utc)
        elapsed_time = self._calculate_elapsed_time(time_utc, current_time_utc)
        return (f"{time_utc.strftime('%Y-%m-%d %H:%M:%S UTC')} (Elapsed: {elapsed_time})")

    # Local method to get the file birth time (creation time).
    def _get_birth_time(self):
        """
        Retrieves the file birth time (creation time) if available.

        Returns:
            str: Formatted birth time or an error message.
        """
        try:
            birth_time_utc = datetime.fromtimestamp(self.file_stat.st_birthtime,
                                                     timezone.utc)
            elapsed_time = self._calculate_elapsed_time(birth_time_utc)
            return (f"{birth_time_utc.strftime('%Y-%m-%d %H:%M:%S UTC')} (Elapsed: {elapsed_time})")
        except AttributeError:
            return "Not available"

    # Local method to get the file group name.
    def _get_group(self):
        if platform.system() != 'Windows':
            import grp
            return grp.getgrgid(self.file_stat.st_gid).gr_name
        else:
            import win32security
            try:
                sd = win32security.GetFileSecurity(self.file_path, win32security.GROUP_SECURITY_INFORMATION)
                group_sid = sd.GetSecurityDescriptorGroup()
                return str(group_sid)
            except Exception as e:
                return f"Error: {e}"

    # Local method to get the file mode type.
    def _get_mode_type(self, st_mode):
        if stat.S_ISDIR(st_mode):
            return 'Directory'
        elif stat.S_ISREG(st_mode):
            return 'Regular File'
        elif stat.S_ISLNK(st_mode):
            return 'Symbolic Link'
        else:
            return 'Other'

    # Local method to get the file owner name.
    def _get_owner(self):
        if platform.system() != 'Windows':
            import pwd
            return pwd.getpwuid(self.file_stat.st_uid).pw_name
        else:
            import win32security
            try:
                sd = win32security.GetFileSecurity(self.file_path, win32security.OWNER_SECURITY_INFORMATION)
                owner_sid = sd.GetSecurityDescriptorOwner()
                return str(owner_sid)
            except Exception as e:
                return f"Error: {e}"

    # Static local method to translate Windows file attribute numbers to names.
    @staticmethod
    def _trans_file_attribs(attr_number):
        """
        Translates Windows file attribute numbers to human-readable names.

        Args:
            attr_number (int): The attribute number to translate.

        Returns:
            list: A list of attribute names corresponding to the attribute number.
        """
        file_attributes_dict = {
            1: "Read-Only",
            2: "Hidden",
            4: "System",
            16: "Directory",
            32: "Archive",
            64: "Device",
            128: "Normal",
            256: "Temporary",
            512: "Sparse File",
            1024: "Reparse Point",
            2048: "Compressed",
            4096: "Offline",
            8192: "Not Content Indexed",
            16384: "Encrypted"
            # Add other attributes as needed
        }

        attributes = []
        for bit, name in file_attributes_dict.items():
            if attr_number & bit:
                attributes.append(name)

        return attributes if attributes else ["None"]

    # Public method to detect file encoding, confidence, and language (if possible).
    def detect_encoding(self):
        """
        Detects the file encoding, confidence level, and if possible, the language used in the file.

        This method utilizes charset_normalizer (chardet) to analyze the raw data read from the file
        and determine the encoding, confidence, and language.

        Returns:
            dict: A dictionary containing the encoding, confidence, language, and presence of BOM.
        """
        encoding_info = {}

        # Use the read_file method to get raw data
        raw_data = self.read_file()

        # Detect encoding and language using chardet
        detected_encoding = chardet.detect(raw_data)
        encoding_info['encoding'] = detected_encoding.get('encoding')
        encoding_info['confidence'] = detected_encoding.get('confidence')
        encoding_info['language'] = detected_encoding.get('language')

        # Check for BOMs
        utf8_bom = b'\xef\xbb\xbf'
        utf16_be_bom = b'\xfe\xff'
        utf16_le_bom = b'\xff\xfe'
        utf32_be_bom = b'\x00\x00\xfe\xff'
        utf32_le_bom = b'\xff\xfe\x00\x00'

        bom_detected = False
        if raw_data.startswith(utf8_bom) and detected_encoding.get('encoding').lower().startswith('utf-8'):
            bom_detected = True
        elif raw_data.startswith(utf16_be_bom) and detected_encoding.get('encoding').lower().startswith('utf-16'):
            bom_detected = True
        elif raw_data.startswith(utf16_le_bom) and detected_encoding.get('encoding').lower().startswith('utf-16'):
            bom_detected = True
        elif raw_data.startswith(utf32_be_bom) and detected_encoding.get('encoding').lower().startswith('utf-32'):
            bom_detected = True
        elif raw_data.startswith(utf32_le_bom) and detected_encoding.get('encoding').lower().startswith('utf-32'):
            bom_detected = True

        encoding_info['has_BOM'] = bom_detected

        return encoding_info

    # Public method to detect natural language and confidence level.
    def detect_language(self, seed=0):
        """
        Detects the natural language and its confidence level used in the file.

        This method uses the langdetect library to analyze the text data and determine the language
        probabilities. The method reads a portion of the file, decodes it using the detected encoding,
        and then performs language detection.

        Args:
            seed (int, optional): Seed for the langdetect library for consistent results. Defaults to 0.

        Returns:
            dict: A dictionary containing detected languages and their probabilities, or an error message if detection fails.
        """
        langdetect.DetectorFactory.seed = seed
        language_info = {}

        try:
            # Use the read_file method to get raw data
            raw_data = self.read_file()

            # Detect encoding if not already detected
            if not hasattr(self, 'detected_encoding') or not self.detected_encoding:
                self.detected_encoding = chardet.detect(raw_data)

            # Decode the raw data using the detected encoding
            text_data = raw_data.decode(self.detected_encoding.get('encoding'))

            # Detect language using langdetect.detect
            probabilities = langdetect.detect_langs(text_data)
            language_info['languages'] = {str(lang.lang): lang.prob
                                          for lang in probabilities}

        except Exception as e:
            language_info['error'] = f"Language detection failed: {e}"

        return language_info

    # Public method to determine the type of line endings used in the file.
    def determine_line_endings(self):
        """
        Determines the type of line endings used in the file.

        This method reads a portion of the file, decodes it using the detected encoding or a default,
        and then checks for the presence of different types of line endings such as CRLF (Windows),
        CR (Mac OS Classic), and LF (Unix/Linux, Mac OS X).

        Returns:
            str: A string representing the type of line endings found, or 'Unknown' if none are detected.
        """
        raw_data = self.read_file()

        # Decode raw data using detected encoding or a default
        encoding = self.detected_encoding.get('encoding') if hasattr(self, 'detected_encoding') and self.detected_encoding else 'utf-8'
        text_data = raw_data.decode(encoding, errors='replace')

        # Check for different types of line endings
        if '\r\n' in text_data:
            return 'CRLF (Windows)'
        elif '\r' in text_data:
            return 'CR (Mac OS Classic)'
        elif '\n' in text_data:
            return 'LF (Unix/Linux, Mac OS X)'
        else:
            return 'Unknown'

    # Public method to get os.stat() file access control gen_attributes.
    def get_fac_attributes(self):
        """
        Retrieves file access control attributes including owner, group, and permissions.

        This method uses platform-specific calls to obtain the owner and group information
        and utilizes the stat module to get file permission details.

        Returns:
            dict: A dictionary containing the owner, group, and permissions of the file.
        """
        fac_attributes = {
            'owner': self._get_owner(),
            'group': self._get_group(),
            'permissions': stat.filemode(self.file_stat.st_mode),
        }
        return fac_attributes

    # Public method to get os.stat() gen_attributes.
    def get_gen_attributes(self):
        """
        Retrieves general attributes of the file including mode, size, device, inode, and number of links.

        This method extracts various attributes using the os.stat() function and formats them for readability.

        Returns:
            dict: A dictionary containing the mode, size, device, inode, and number of links of the file.
        """
        gen_attributes = {
            'path': self.file_path,
            'mode': self._get_mode_type(self.file_stat.st_mode),
            'size': "{:,}".format(self.file_stat.st_size),
            'device': self.file_stat.st_dev,
            'inode': self.file_stat.st_ino,
            'n_links': self.file_stat.st_nlink,
        }
        return gen_attributes

    # Public method to get file hash.
    def get_hash(self, algorithm='sha256'):
        """
        Method to calculate the hash of the file using the specified algorithm.
        Defaults to SHA256, but other algorithms supported by hashlib can be used.

        :param algorithm: String, name of the hashing algorithm to use.
        :return: The hexadecimal hash string of the file.
        """
        if algorithm.lower() not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        hash_func = hashlib.new(algorithm.lower())

        try:
            with open(self.file_path, 'rb') as file:
                for chunk in iter(lambda: file.read(4096), b''):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except IOError as e:
            raise IOError(f"Error reading file for hashing: {e}")

    # Public method to get MIME file type information.
    def get_mime_info(self):
        """
        Determines the MIME type and extension of the file and checks if they match.

        Utilizes the python-magic library to identify the MIME type and compares it with the expected MIME type
        based on the file extension. Also checks for common compression formats.

        Returns:
            dict: A dictionary containing the file extension, MIME type, extension match, and compression information.
        """
        file_type_info = {
            'extension': os.path.splitext(self.file_path)[1].lower(),
            'mime_type': magic.from_file(self.file_path, mime=True)
        }

        expected_mime_type = mimetypes.guess_type(self.file_path)[0]
        file_type_info['ext_match'] = (file_type_info['mime_type'] == expected_mime_type)

        # Check for common compression formats
        compression_formats = {
            '.zip': 'application/zip',
            '.gz': 'application/gzip',
            '.bz2': 'application/x-bzip2',
            '.tar': 'application/x-tar',
            # Add other formats as needed
        }

        if file_type_info['extension'] in compression_formats:
            file_type_info['is_compressed'] = True
            file_type_info['compression_type'] = compression_formats[file_type_info['extension']]
        elif file_type_info['mime_type'] in compression_formats.values():
            file_type_info['is_compressed'] = True
            file_type_info['compression_type'] = [k for k, v in compression_formats.items() if v == file_type_info['mime_type']][0]
        else:
            file_type_info['is_compressed'] = False
            file_type_info['compression_type'] = None

        return file_type_info

    # Public method to get OS-specific file attributes.
    def get_os_attributes(self):
        """
        Retrieves operating system-specific file metadata.

        Depending on the OS, this method collects different sets of data such as blocks, blksize, rdev for Unix/Linux systems,
        and file_attributes, reparse_tag for Windows systems.

        Returns:
            dict: A dictionary containing OS-specific file metadata.
        """
        os_specific_attrs = {}

        if self.op_sys in ['Linux', 'Unix', 'FreeBSD', 'Solaris', 'macOS']:
            # Unix/Linux attributes
            try:
                os_specific_attrs['blocks'] = self.file_stat.st_blocks
                os_specific_attrs['blksize'] = self.file_stat.st_blksize
                os_specific_attrs['rdev'] = self.file_stat.st_rdev
            except AttributeError:
                pass  # These attributes are not available on all Unix systems

            if self.op_sys == 'FreeBSD':
                try:
                    os_specific_attrs['gen'] = self.file_stat.st_gen
                except AttributeError:
                    pass

            if self.op_sys == 'Solaris':
                try:
                    os_specific_attrs['fstype'] = self.file_stat.st_fstype
                except AttributeError:
                    pass

            if self.op_sys == 'macOS':
                try:
                    os_specific_attrs['rsize'] = self.file_stat.st_rsize
                    os_specific_attrs['creator'] = self.file_stat.st_creator
                    os_specific_attrs['type'] = self.file_stat.st_type
                except AttributeError:
                    pass

        if self.op_sys == 'Windows':
            # Windows-specific attributes
            try:
                os_specific_attrs['file_attributes'] = \
                FileMetadataExtractor._trans_file_attribs(
                    self.file_stat.st_file_attributes)

                os_specific_attrs['reparse_tag'] = self.file_stat.st_reparse_tag
            except AttributeError:
                pass

        return os_specific_attrs

    # Public method to get file timestamps.
    def get_timestamps(self):
        """
        Retrieves the accessed, modified, created, and birth times of the file.

        Formats these timestamps into a human-readable format and calculates the elapsed time since each timestamp.

        Returns:
            dict: A dictionary containing formatted timestamps and their corresponding elapsed times.
        """
        current_time_utc = datetime.now(timezone.utc)
        timestamps = {
            'accessed_time': self._format_timestamp(self.file_stat.st_atime, current_time_utc),
            'modified_time': self._format_timestamp(self.file_stat.st_mtime, current_time_utc),
            'created_time': self._format_timestamp(self.file_stat.st_ctime, current_time_utc),
            'birthed_time': self._get_birth_time()
        }
        return timestamps

    # Public method to read a portion of the file and load raw data.
    def read_file(self, num_bytes=None):
        """
        Method to read a portion of the file and load raw data.
        :param num_bytes: Number of bytes to read from the file.
        :return: Raw data read from the file.
        """
        if self.raw_data is None:
            try:
                with open(self.file_path, 'rb') as file:
                    self.raw_data = file.read(num_bytes)
            except Exception as e:
                raise IOError(f"Error reading file: {e}")
        return self.raw_data

    #ToDo: Add VirusTotal API integration to check for malware.

    # Public method to generate a comprehensive report of the extracted metadata.
    def generate_report(self):
        """
        Compiles the extracted metadata into a comprehensive report.

        The method gathers all the extracted file metadata, including basic file information, access control,
        MIME type, encoding, language, OS-specific attributes, and file hashes. It records the script's start
        and end times and calculates the total elapsed time.

        Returns:
            str: A multiline string representing the complete metadata report.
        """
        report = []

        # Record script start time in UTC
        start_time = datetime.now(timezone.utc)
        report.append(f"Started {self.__class__.__name__} at {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # Get starting file hash
        try:
            start_hash = self.get_hash()
            report.append(f"\nStarting File Hash (SHA256): {start_hash}")
        except Exception as e:
            report.append(f"\nError computing starting file hash: {e}")

        report.append("\nBasic File Information:")
        report.extend([f"  {key}: {value}" for key, value in self.get_gen_attributes().items()])

        report.append("\nAccess Control Information:")
        report.extend([f"  {key}: {value}" for key, value in self.get_fac_attributes().items()])

        report.append("\nTimestamp Information (Elapsed: Y/M/D, h:m:s):")
        report.extend([f"  {key}: {value}" for key, value in self.get_timestamps().items()])

        report.append("\nFile Type Information:")
        report.extend([f"  {key}: {value}" for key, value in self.get_mime_info().items()])

        report.append("\nFile Encoding Information:")
        report.extend([f"  {key}: {value}" for key, value in self.detect_encoding().items()])
        report.append(f"  line endings: {self.determine_line_endings()}")

        report.append("\nAdditional Language Information:")
        report.extend([f"  {key}: {value}" for key, value in self.detect_language().items()])

        report.append("\nOS-Specific Information:")
        report.extend([f"  {key}: {value}" for key, value in self.get_os_attributes().items()])

        # Get ending file hash
        try:
            end_hash = self.get_hash()
            report.append(f"\nEnding File Hash (SHA256): {end_hash}")
            report.append(f"Hashes Match: {start_hash == end_hash}")
        except Exception as e:
            report.append(f"\nError computing ending file hash: {e}")

        # Record script end time in UTC
        end_time = datetime.now(timezone.utc)
        end_time_str = end_time.strftime("%Y-%m-%d %H:%M:%S UTC")

        # Calculate and report script elapsed time
        elapsed_time = (end_time - start_time).total_seconds()
        elapsed_time_str = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))
        report.append(f"\nElapsed Time: {elapsed_time_str}")

        report.append(f"\nFinished {self.__class__.__name__} at {end_time_str}")

        return "\n".join(report)


# Define Script Functions
def create_metadata_report(file_path, report_path):
    extractor = FileMetadataExtractor(file_path)
    report = extractor.generate_report()

    try:
        with open(report_path, 'w') as report_file:
            report_file.write(report)
    except IOError as e:
        print(f"Error writing report to file: {e}")
    else:
        print(f"Report saved to: {report_path}")


def parse_arguments():
    parser = argparse.ArgumentParser(description="File Metadata Extraction Tool")
    parser.add_argument("file_path", help="Path to the file for metadata extraction")
    parser.add_argument("report_path", help="Path where the metadata report will be saved")
    return parser.parse_args()

def main():
    args = parse_arguments()
    if os.path.exists(args.file_path):
        create_metadata_report(args.file_path, args.report_path)
    else:
        print(f"Error: File '{args.file_path}' does not exist.")


# Main Body of Script
if __name__ == "__main__":
    main()
    print("File Metadata Extraction Script Execution Complete.")


# References
"""
Coding assistance from:
GitHub. (2023). Copilot Extension for VSCode [Computer software]. https://github.com/features/copilot

OpenAI. (2023). ChatGPT 4 (Nov 6 version) [Large language model]. https://chat.openai.com/share/{chat_id}

"""