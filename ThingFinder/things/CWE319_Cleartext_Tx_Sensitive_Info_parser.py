import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE319Parser(IngestClass):

    def parser(self, code):
        # Regular expressions to match potential vulnerable patterns
        connect_socket_pattern = re.compile(r'connect\(.*socket\(AF_INET, SOCK_STREAM, IPPROTO_TCP\)\)', re.IGNORECASE)
        listen_socket_pattern = re.compile(r'listen\(.*socket\(AF_INET, SOCK_STREAM\)\)', re.IGNORECASE)
        recv_pattern = re.compile(r'recv\(.*char\*\(.*wchar_t\+\)\)', re.IGNORECASE)
        logonuser_pattern = re.compile(r'LogonUserW\(.*password\)', re.IGNORECASE)

        # Check if any of the patterns match in the code
        if connect_socket_pattern.search(code) or listen_socket_pattern.search(code) or recv_pattern.search(code):
            # If a match is found, check if the password is being read from a network connection
            if 'recv' in code and 'password' in code:
                return True

        # Check if the logonuser function is being used with a password
        if logonuser_pattern.search(code):
            if 'password' in code:
                return True

        # If no matches are found, return False
        return False