import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE369_DivideByZeroParser(IngestClass):

    def __init__(self):
        super().__init__()
        self.regex_divide = re.compile(r'(\d+) / (\d+)')

    def parser(self, code):
        # Find all occurrences of division operations in the code
        matches = self.regex_divide.findall(code)

        for division in matches:
            dividend, divisor = division
            # Check if the divisor is zero
            if int(divisor) == 0:
                return True

        return False
