import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE325Parser(IngestClass):

    def parser(self, code):
        # Initialize a variable to store the result
        result = False

        # Use regex to find the function calls related to the CWE
        function_calls = re.findall(r'CWE325_Missing_Required_Cryptographic_Step__w32_[a-zA-Z0-9_]+', code)

        # If any of the function calls are found, the vulnerability is present
        if function_calls:
            result = True

        return result
