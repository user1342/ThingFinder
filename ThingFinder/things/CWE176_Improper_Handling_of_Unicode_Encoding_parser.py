import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 
   
class CWE176Parser(IngestClass):

    def __init__(self):
        super().__init__()
        self.wchar_pattern = r'wchar_t\s*(\*|\&)\s*data'
        self.wcscpy_pattern = r'wcscpy\(\s*(\w+)\s*,\s*L\'\'\w*\\u[0-9a-f]{4}\w*\\u[0-9a-f]{4}\w*\\u[0-9a-f]{4}\w*\\u[0-9a-f]{4}\w*\\u[0-9a-f]{4}\w*\\u[0-9a-f]{4}\w*\\u[0-9a-f]{4}\w*\)'
        self.WideCharToMultiByte_pattern = r'WideCharToMultiByte\(\s*(\w+),\s*(\w+),\s*(\w+),\s*(-?\d+),\s*(\w+),\s*(-?\d+),\s*(-?\d+),\s*(-?\d+)\)'

    def parser(self, code):
        if not re.search(self.wchar_pattern, code, re.IGNORECASE):
            return False

        if re.search(self.wcscpy_pattern, code, re.IGNORECASE):
            # Check if the Unicode string is too long
            unicode_string_length = len(re.findall(r'\\u[0-9a-f]{4}', self.wcscpy_pattern)) * 4
            if unicode_string_length > 100:
                return True

        if re.search(self.WideCharToMultiByte_pattern, code, re.IGNORECASE):
            # Check if the destination buffer size is not checked before conversion
            required_size = int(re.findall(r'(-?\d+)', self.WideCharToMultiByte_pattern[-1])[0])
            if not re.search(r'if\s*\(\s*required_size\s*<=\s*10\s*\)', code, re.IGNORECASE):
                return True

        return False