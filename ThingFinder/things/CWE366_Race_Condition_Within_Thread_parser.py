import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE366Parser(IngestClass):

    def parser(self, code):
        # Initialize the flag to False, indicating no vulnerability found
        vulnerability_found = False

        # Regular expression patterns to match the vulnerable code patterns
        pattern_bad = re.compile(r'srand\(\s*\(\s*time\(\s*\(\s*\)\s*\)\s*\)\s*\);\s*globalArgc\s*=\s*argc;\s*globalArgv\s*=\s*argv;')
        pattern_good = re.compile(r'srand\(\s*\(\s*time\(\s*\(\s*\)\s*\)\s*\)\s*;')

        # Check if the bad pattern is present in the code
        if pattern_bad.search(code):
            vulnerability_found = True

        # Check if the good pattern is present in the code (to ensure the good pattern is also present)
        if not pattern_good.search(code):
            vulnerability_found = True

        # Return the result as a boolean value
        return vulnerability_found
