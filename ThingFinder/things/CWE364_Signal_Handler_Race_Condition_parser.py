import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE364Parser(IngestClass):

    def __init__(self):
        super().__init__()
        self.signal_handler_pattern = re.compile(r'signal\((\w+), (\w+), (\w+)\)')
        self.signal_handler_function_pattern = re.compile(r'(\w+)_handler')

    def parser(self, code):
        # Find all signal calls in the code
        signal_calls = self.signal_handler_pattern.findall(code)

        # Iterate through each signal call
        for signal_call in signal_calls:
            # Extract the signal name, signal number, and signal handler function name
            signal_name, signal_number, handler_function_name = signal_call

            # Check if the signal handler function name matches the pattern for a vulnerable function
            if self.signal_handler_function_pattern.match(handler_function_name):
                # If the signal handler function name matches the pattern, return True to indicate a vulnerability
                return True

        # If no vulnerable signal handler functions are found, return False
        return False
