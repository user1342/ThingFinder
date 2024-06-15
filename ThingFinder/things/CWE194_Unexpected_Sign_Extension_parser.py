import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE194Parser(IngestClass):

    def parser(self, code):
        # Initialize variables
        vulnerability_found = False

        # Find all instances of strncpy or memcpy
        strncpy_or_memcpy = re.findall(r'strncpy|memcpy', code, re.IGNORECASE)

        # Iterate through each instance of strncpy or memcpy
        for instance in strncpy_or_memcpy:
            # Extract the surrounding code
            surrounding_code = code[code.index(instance) - 100: code.index(instance) + 500]

            # Check if the code contains a negative number
            if re.search(r'-', surrounding_code, re.IGNORECASE):
                # Check if the code contains strncpy or memcpy with a length variable
                length_variable = re.search(r'(\w+)\s*<\s*(\w+)\s*>', surrounding_code, re.IGNORECASE)
                if length_variable:
                    # Check if the length variable is negative or unsigned and overflows
                    if int(length_variable.group(2)) < 0 or int(length_variable.group(2)) > 2147483647:
                        vulnerability_found = True

        # Return the result
        return vulnerability_found
