import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE121Parser(IngestClass):

    def parser(self, code):
        # Regular expressions for matching potential buffer overflow scenarios
        buffer_overflow_patterns = [
            # Pattern 1: wcscat with alloca
            r'alloca\(\s*(\w+)\s*\)\s*wcscat\(\s*(\w+),\s*(\w+)\s*\)',
            # Pattern 2: wcscpy with list
            r'list\<(\w+)\>\s*wcscpy\(\s*(\w+),\s*(\w+)\s*\)',
            # Pattern 3: wcscat with class constructor and destructor
            r'class\s+(\w+)\s*\(\s*(\w+)\s*\)\s*wcscat\(\s*(\w+),\s*(\w+)\s*\)',
        ]

        for pattern in buffer_overflow_patterns:
            match = re.search(pattern, code, re.DOTALL)
            if match:
                return True

        return False
