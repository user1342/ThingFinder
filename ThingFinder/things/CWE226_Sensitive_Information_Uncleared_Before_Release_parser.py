import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE226Parser(IngestClass):

    def parser(self, code):
        # Initialize a variable to store the result
        result = False

        # Use regex to find potential alloca calls in the code
        alloca_pattern = re.compile(r'alloca\(\(([^)]+)\)\s*;')
        alloca_matches = alloca_pattern.finditer(code)

        # Iterate through the matches and check if they contain sensitive information
        for match in alloca_matches:
            # Extract the arguments passed to alloca
            args = match.group(1)

            # Use regex to find potential sensitive information in the arguments
            sensitive_pattern = re.compile(r'(\b(password|ssn|credit_card|ssn|email|login|api_key)\b)')
            sensitive_match = sensitive_pattern.search(args)

            # If sensitive information is found, set the result to True
            if sensitive_match:
                result = True
                break

        # Return the result
        return result