import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE195Parser(IngestClass):

    def parser(self, code):
        # Initialize a dictionary to store the occurrences of malloc, calloc, and realloc functions
        function_occurrences = {}
        function_occurrences['malloc'] = 0
        function_occurrences['calloc'] = 0
        function_occurrences['realloc'] = 0

        # Initialize a dictionary to store the occurrences of strncpy, memcpy, memmove, and memset functions
        string_functions = {}
        string_functions['strncpy'] = 0
        string_functions['memcpy'] = 0
        string_functions['memmove'] = 0
        string_functions['memset'] = 0

        # Find all occurrences of malloc, calloc, realloc, strncpy, memcpy, memmove, and memset functions
        for line in code.split('\n'):
            if re.search(r'malloc\(', line):
                function_occurrences['malloc'] += 1
            elif re.search(r'calloc\(', line):
                function_occurrences['calloc'] += 1
            elif re.search(r'realloc\(', line):
                function_occurrences['realloc'] += 1
            elif re.search(r'strncpy\(', line):
                string_functions['strncpy'] += 1
            elif re.search(r'memcpy\(', line):
                string_functions['memcpy'] += 1
            elif re.search(r'memmove\(', line):
                string_functions['memmove'] += 1
            elif re.search(r'memset\(', line):
                string_functions['memset'] += 1

        # Check if there is a potential vulnerability
        if (function_occurrences['malloc'] > 0 or function_occurrences['calloc'] > 0 or function_occurrences['realloc'] > 0) and (string_functions['strncpy'] > 0 or string_functions['memcpy'] > 0 or string_functions['memmove'] > 0 or string_functions['memset'] > 0):
            # Check if there is a negative number involved in the malloc, calloc, or realloc function
            negative_number = False
            for line in code.split('\n'):
                if re.search(r'-[0-9]+', line):
                    negative_number = True
                    break

            if negative_number:
                return True

        return False