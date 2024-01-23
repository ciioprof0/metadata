#!/usr/bin/env python
# coding: utf-8

"""
FindMyPath Module
-----------------
A module to find paths to files or directories and provide absolute, unexpanded, and relative paths.

Class:
- PathFinder: A class to handle path finding operations.
"""

# Import Standard Libraries
import argparse                 # Parser for command-line options, arguments and sub-commands
import chardet                  # Universal encoding detector
import glob                     # Unix style pathname pattern expansion
import datetime                 # Basic date and time types
import logging                  # Logging module for debugging
import os                       # Miscellaneous operating system interfaces
import platform                 # Access to underlying platform’s identifying data
import sys

from main import detect_encoding                      # System-specific parameters and functions


# Set Global Variables
SEARCH_PATTERN = "example*.csv"
SEARCH_ROOT = "~/Code/"
GREEDY = False


# Define Classes
class myPathFinder:
    def __init__(self, pattern="*.csv", search_root="~/Code/", greedy=False):
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("Search pattern must be a non-empty string.")
        if not os.path.isdir(os.path.expanduser(search_root)):
            raise ValueError(f"Search root '{search_root}' is not a valid directory.")

        self.pattern = pattern
        self.search_root = os.path.expanduser(search_root)
        self.greedy = greedy

        logging.info(f"Initialized PathFinder with pattern: {self.pattern}, search root: {self.search_root}, greedy: {self.greedy}")

    def find_path(self):
        logging.info(f"find_path called with pattern: {self.pattern}, root: {self.search_root}")
        try:
            if self.greedy:
                found_paths = []
                for root, dirs, files in os.walk(self.search_root):
                    logging.debug(f"Searching in directory: {root}")
                    for file in files:
                        if glob.fnmatch.fnmatch(file, self.pattern):
                            found_path = os.path.join(root, file)
                            found_paths.append(found_path)
                            logging.debug(f"Found path: {found_path}")
                return found_paths if found_paths else None
            else:
                cwd = os.getcwd()
                search_root_abs = os.path.abspath(os.path.expanduser(self.search_root))
                while True:
                    logging.debug(f"Checking directory: {cwd}")
                    for root, dirs, files in os.walk(cwd):
                        for file in files:
                            if glob.fnmatch.fnmatch(file, self.pattern):
                                possible_path = os.path.join(root, file)
                                if os.path.isfile(possible_path):
                                    logging.info(f"Found path: {possible_path}")
                                    return possible_path

                    # Move up one directory level
                    parent_dir = os.path.dirname(cwd)
                    if parent_dir == cwd or not cwd.startswith(search_root_abs):
                        # If reached the top of the directory tree or moved beyond the search root
                        logging.debug(f"Reached the search root or top of the directory tree: {cwd}")
                        break
                    cwd = parent_dir

            logging.info("No paths found.")
            return None

        except Exception as e:
            logging.error(f"Error during path search: {type(e).__name__}: {e}")
            return None

    def get_abs_path(self):
        logging.info("Getting absolute paths.")
        try:
            found_paths = self.find_path()
            if isinstance(found_paths, list):
                abs_paths = [os.path.abspath(path) for path in found_paths]
                logging.info(f"Absolute paths: {abs_paths}")
                return abs_paths
            elif found_paths:
                abs_path = os.path.abspath(found_paths)
                logging.info(f"Absolute path: {abs_path}")
                return abs_path
            else:
                logging.info("No paths found.")
                return None
        except Exception as e:
            logging.error(f"Exception in get_abs_path: {type(e).__name__}: {e}")
            return None

    def get_var_path(self, paths):
        logging.info("Getting variable paths.")
        try:
            def convert_path(path):
                user_home_keys = ['USERPROFILE', 'HOME']
                for key in user_home_keys:
                    env_value = os.environ.get(key)
                    if env_value and path.startswith(env_value):
                        var_path = path.replace(env_value, f"%{key}%")
                        logging.debug(f"Converted {path} to {var_path}")
                        return var_path
                return path

            if isinstance(paths, list):
                var_paths = [convert_path(path) for path in paths]
                logging.info(f"Variable paths: {var_paths}")
                return var_paths
            elif paths:
                var_path = convert_path(paths)
                logging.info(f"Variable path: {var_path}")
                return var_path
            else:
                logging.info("No paths found.")
                return None
        except Exception as e:
            logging.error(f"Exception in get_var_path: {type(e).__name__}: {e}")
            return None

    def get_rel_path(self, base_path, paths):
        logging.info("Getting relative paths.")
        try:
            def convert_path(path):
                rel_path = os.path.relpath(path, base_path)
                logging.debug(f"Converted {path} to {rel_path}")
                return rel_path

            if isinstance(paths, list):
                rel_paths = [convert_path(path) for path in paths]
                logging.info(f"Relative paths: {rel_paths}")
                return rel_paths
            elif paths:
                rel_path = convert_path(paths)
                logging.info(f"Relative path: {rel_path}")
                return rel_path
            else:
                logging.info("No paths found.")
                return None
        except Exception as e:
            logging.error(f"Exception in get_rel_path: {type(e).__name__}: {e}")
            return None
 
    def detect_encoding(self, file_path, sample_size=1024):
        """
        Detects the encoding of a file.

        Parameters:
        file_path (str): The path to the file whose encoding needs to be detected.
        sample_size (int): The number of bytes to read from the file for encoding detection.
                           Set to -1 to read the entire file.

        Returns:
        str: The detected encoding of the file.
        """
        logging.info(f"Detecting encoding for: {file_path}")
        try:
            with open(file_path, 'rb') as file:
                if sample_size == -1:
                    contents = file.read()  # Read the entire file
                else:
                    contents = file.read(sample_size)  # Read only the specified sample size

            result = chardet.detect(contents)
            encoding = result['encoding']
            logging.info(f"Detected encoding: {encoding} for file: {file_path}")
            return encoding
        except Exception as e:
            logging.error(f"Error in detect_encoding: {type(e).__name__}: {e}")
            return None

# Define Functions
def initialize_logging(log_level=logging.DEBUG):
    """
    Initialize logging settings. Log file is saved to the directory where the script resides.
    """
    script_directory = os.path.dirname(os.path.abspath(__file__))
    log_directory = os.path.join(script_directory, 'logs')
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)

    script_name = os.path.splitext(os.path.basename(__file__))[0]
    current_time = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    log_file_name = f"{script_name}_{current_time}.log"
    log_file_path = os.path.join(log_directory, log_file_name)

    logging.basicConfig(filename=log_file_path, level=log_level,
                        format='%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s')
    logging.info("Logging initialized.")
    logging.info(f"Script directory: {script_directory}")
    logging.info(f"Operating System: {os.name}, Platform: {os.sys.platform}, Python Version: {sys.version}")

    return


def main(pattern, search_root, greedy):
    logging.info(f"Starting main with pattern: {pattern} and root: {search_root}")
    # Usage Example
    finder = myPathFinder(pattern, search_root, greedy)
    abs_path = finder.get_abs_path()
    var_path = finder.get_var_path(abs_path)
    rel_path = finder.get_rel_path(os.path.dirname(__file__), abs_path)
    print(f"abs_path: {abs_path}")
    print(f"var_path: {var_path}")
    print(f"rel_path: {rel_path}")
    print(f"cwd_path: {os.getcwd()}")

    # Convert var_path and rel_path back to absolute paths
    var_path_abs = os.path.abspath(os.path.expandvars(var_path))
    rel_path_abs = os.path.abspath(os.path.join(os.path.dirname(__file__), rel_path))
    abs_path_mod = abs_path

    # Check if the operating system is Windows
    if platform.system().lower() == "windows":
        var_path_abs = var_path_abs.lower()
        rel_path_abs = rel_path_abs.lower()
        abs_path_mod = abs_path.lower()

    print(f"var_path_abs: {var_path_abs}")
    print(f"rel_path_abs: {rel_path_abs}")

    # Compare with abs_path
    print("Var Path matches:", var_path_abs == abs_path_mod)
    print("Rel Path matches:", rel_path_abs == abs_path_mod)

    # Check file existence
    print("Var Path exists:", os.path.exists(var_path_abs))
    print("Rel Path exists:", os.path.exists(rel_path_abs))

    # If it's a file, try opening it (as an example)
    if os.path.isfile(abs_path):
        try:
            with open(var_path_abs, 'r') as file:
                logging.info(f"Var Path opened {file}")
        except IOError:
            logging.error(f"Var Path could not open {file}")

        try:
            with open(rel_path_abs, 'r') as file:
               logging.info(f"Rel Path opened {file}")
        except IOError:
            logging.error(f"Rel Path could not open {file}")

    logging.info("Main function completed successfully.")
    logging.info(f"Total paths found: {len(abs_path) if abs_path else 0}")
    return


# Main Body of Module
if __name__ == "__main__":
    initialize_logging()

    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="FindMyPath: A tool to find file paths and provide absolute, unexpanded, and relative paths.")
    parser.add_argument("search_pattern", nargs='?', default=SEARCH_PATTERN,
                        help="File search pattern (e.g., '*.txt' or 'example.csv'). Defaults to '*.csv'")
    parser.add_argument("search_root", nargs='?', default=SEARCH_ROOT,
                        help="Root directory to start the search. Defaults to user home dir '~'")
    parser.add_argument("-g", "--greedy", action="store_true", default=GREEDY,
                        help="Enable greedy search to find all matching files in the search root")
    args = parser.parse_args()
    args.search_root = os.path.expanduser(args.search_root)

    try:
        main(args.search_pattern, args.search_root, args.greedy)
        logging.info("The script completed successfully.")
        print("The script completed successfully.")
        sys.exit(0)     # Exit with success

    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
        print(f"A ValueError occurred: {ve}")
        sys.exit(65)    # Exit with a value error

    except FileNotFoundError as fnfe:
        logging.error(f"FileNotFoundError: {fnfe}")
        print(f"A FileNotFoundError occurred: {fnfe}")
        sys.exit(66)    # Exit with a file not found error

    except Exception as e:
        logging.error(f"An unexpected error occurred: {type(e).__name__}: {e}")
        print(f"An unexpected error occurred: {type(e).__name__}: {e}")
        sys.exit(70)    # Exit with an unexpected error

    finally:
        for handler in logging.root.handlers[:]:
            handler.close()

# End of Script


# References
"""
Coding assistance from:
GitHub. (2023). Copilot Extension for VSCode [Computer software]. https://github.com/features/copilot

OpenAI. (2023). ChatGPT 4 (Nov 6 version) [Large language model]. https://chat.openai.com/share/{chat_id}

"""