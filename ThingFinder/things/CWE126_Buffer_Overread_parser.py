import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE126Parser(IngestClass):

    def __init__(self):
        super().__init__()
        self.memmove_pattern = re.compile(r'memmove\((.+), (.+), (.+)\)')
        self.wmemset_pattern = re.compile(r'wmemset\((.+), (.+), (.+)\)')
        self.wchar_t_alloca_pattern = re.compile(r'alloca\((.+)\)')

    def parser(self, code):
        # Check for memmove function usage
        match = self.memmove_pattern.search(code)
        if match:
            src, dest, length = match.groups()
            if int(length) > len(dest.strip('[]')):
                return True

        # Check for wmemset function usage
        match = self.wmemset_pattern.search(code)
        if match:
            dest, fill_char, length = match.groups()
            if int(length) > len(dest.strip('[]')):
                return True

        # Check for alloca function usage
        match = self.wchar_t_alloca_pattern.search(code)
        if match:
            size = match.group(1)
            if int(size) <= 100:
                return True

        return False
