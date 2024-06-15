import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE259HardCodedPasswordParser(IngestClass):

    def __init__(self):
        super().__init__()
        self.password_regex = r'(?<=\s)(\'[^\']*\'|\"[^\"]*\")'

    def parser(self, code):
        # Find all occurrences of strings that could be passwords
        password_occurrences = re.findall(self.password_regex, code)

        # Iterate through each occurrence and check if it looks like a password
        for password in password_occurrences:
            if len(password) >= 8 and re.search(r'\d', password):
                # If the string is long enough and contains a digit, it might be a password
                self.add_vulnerability(True)
                return True

        # If no potential passwords were found, there is no vulnerability
        self.add_vulnerability(False)
        return False