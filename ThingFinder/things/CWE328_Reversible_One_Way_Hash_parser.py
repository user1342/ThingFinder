import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE328Parser(IngestClass):

    def parser(self, code):
        # Initialize a set to store the hashing functions we are looking for
        hashing_functions = {"MD2", "MD5", "SHA1"}

        # Use regex to find the function calls in the code
        function_calls = re.findall(r'(CWE328_[A-Z0-9_]+)\(\);', code, re.IGNORECASE)

        # Iterate through the function calls and check if they are hashing functions
        for function in function_calls:
            if function.startswith("CWE328_") and function[7:] in hashing_functions:
                return True

        # If no vulnerable function calls are found, return False
        return False
