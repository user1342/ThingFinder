import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE247Parser(IngestClass):

    def __init__(self):
        super().__init__()
        self.patterns = [
            # Patterns for known bad function calls
            r'CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_\d+_bad\(\);',
            # Patterns for known good function calls (to ignore)
            r'CWE247_Reliance_on_DNS_Lookups_in_Security_Decision__w32_\d+_good\(\);'
        ]

    def parser(self, code):
        for pattern in self.patterns:
            if re.search(pattern, code, re.IGNORECASE):
                return True
        return False