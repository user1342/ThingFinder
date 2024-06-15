import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 
import os

class CWE23RelativePathTraversalParser(IngestClass):

    def parser(self, code):
        # Initialize a dictionary to store the base path and socket functions
        base_path = None
        socket_functions = set()

        # Find the base path and socket functions in the code
        for line in code.split('\n'):
            if re.search(r'#define BASEPATH (.*?) ', line):
                base_path = re.search(r'#define BASEPATH (.*?) ', line).group(1)
            if re.search(r'socket\(', line) and re.search(r'IPPROTO_TCP', line):
                socket_functions.add(line)

        # Check if the base path and socket functions are found
        if base_path and socket_functions:
            # Iterate through the socket function lines
            for line in socket_functions:
                # Extract the arguments of the socket function
                args = re.findall(r'\(.*?\)', line)
                # Check if the arguments contain a variable that starts with the base path
                if any(base_path in arg for arg in args):
                    return True

        # If no vulnerable code is found, return False
        return False