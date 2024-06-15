import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE327Parser(IngestClass):

    def parser(self, code):
        # Initialize a variable to store the result
        result = False

        # Use regex to find function calls related to broken cryptography
        # The regular expression pattern matches function calls with specific names
        # that are known to be vulnerable to CWE327_Use_Broken_Crypto
        pattern = re.compile(r'CWE327_Use_Broken_Crypto__w32_[a-zA-Z0-9_]+')

        # Find all matches of the pattern in the code
        matches = pattern.findall(code)

        # If any matches are found, set the result to True
        if matches:
            result = True

        return result