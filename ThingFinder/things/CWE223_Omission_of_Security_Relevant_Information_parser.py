import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE223Parser(IngestClass):

    def parser(self, code):
        # Define regular expressions for identifying vulnerable patterns
        good_function_calls = r'CWE223_[0-9]+_good\(\);'
        bad_function_calls = r'CWE223_[0-9]+_bad\(\);'

        # Find all good and bad function calls in the code
        good_calls = re.findall(good_function_calls, code)
        bad_calls = re.findall(bad_function_calls, code)

        # If there are any bad function calls, return True (vulnerability present)
        if bad_calls:
            return True

        # If there are no bad function calls and no good function calls, return False (no vulnerability)
        if not good_calls and not bad_calls:
            return False

        # If there are no bad function calls but good function calls are missing, return True (potential vulnerability)
        if not bad_calls and not good_calls:
            return True
