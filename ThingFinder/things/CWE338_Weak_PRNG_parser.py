import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE338Parser(IngestClass):

    def __init__(self):
        super().__init__()
        self.srand_pattern = r'srand\((.*?)\)'

    def parser(self, code):
        # Check if srand function is used with a constant or predictable value
        match = re.search(self.srand_pattern, code)
        if match:
            return True

        # Check if there are any other PRNG functions used
        # (This is a simplification and may not cover all cases)
        # Add more checks for other PRNG functions as needed

        return False
