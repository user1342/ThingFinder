import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE15Parser(IngestClass):

    def parser(self, code):
        # Regular expression patterns to match potential vulnerabilities
        pattern_socket = r'socket\(\s*(\w+)\s*,\s*(\w+)\s*,\s*(\d+)\s*\)'
        pattern_set_hostname = r'SetComputerNameA\(\s*(\w+)\s*\)'

        # Find all occurrences of socket calls and set_hostname calls
        socket_calls = re.findall(pattern_socket, code)
        set_hostname_calls = re.findall(pattern_set_hostname, code)

        # If there is a socket call and a set_hostname call, return True
        if socket_calls and set_hostname_calls:
            return True

        # If there are no matches, return False
        return False