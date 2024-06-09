import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE114Parser(IngestClass):

    def __init__(self):
        super().__init__()
        self.load_library_pattern = r'LoadLibrary[Aa][\w\s]*\('
        self.fopen_pattern = r'fopen\([\w\s]+\,[\s\w\"]*[rR][\w\s]*\)'
        self.fgets_pattern = r'fgets\([\w\s]+\,[\w\s]*\)'

    def parser(self, code):
        if re.search(self.load_library_pattern, code, re.IGNORECASE):
            return True

        if re.search(self.fopen_pattern, code) and re.search(self.fgets_pattern, code):
            return True

        return False