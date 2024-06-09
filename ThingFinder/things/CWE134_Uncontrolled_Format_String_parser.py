import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE134Detector(IngestClass):

    def parser(self, code):
        # Regular expression pattern to match the _vsnwprintf or vwprintf function calls
        pattern = r'(?:\s*_vsnwprintf\s*\(\s*wchar_t\s*\*\s*dest\s*,\s*wint_t\s*count\s*,\s*wchar_t\s*\*\s*format\s*\)\s*;)|(?:\s*vwprintf\s*\(\s*wchar_t\s*\*\s*dest\s*,\s*wchar_t\s*\*\s*format\s*\)\s*;)'

        # Find all matches of the pattern in the code
        matches = re.findall(pattern, code)

        # If there are no matches, return False (no vulnerability)
        if not matches:
            return False

        # Iterate through the matches
        for match in matches:
            # Check if the format string is missing
            if not re.search(r'\w+\*\s*', match):
                return True  # Return True if a vulnerable line is found

        # If no vulnerable line is found, return False
        return False
