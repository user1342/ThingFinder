import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE188Parser(IngestClass):

    def parser(self, code):
        # Initialize the flag to False, indicating no vulnerability found
        vulnerability_found = False

        # Regular expressions to match specific patterns related to CWE188
        union_pattern = re.compile(r'union\s+(\w+\s+=\s+)\w+\s+(\w+\s+=\s+)\w+;')
        struct_pattern = re.compile(r'struct\s+(\w+\s+=\s+)\{.*\};')
        bitfield_pattern = re.compile(r'(\w+\s+=\s+)\{.*\};')

        # Search for union, struct, and bitfield patterns in the code
        union_matches = union_pattern.findall(code)
        struct_matches = struct_pattern.findall(code)
        bitfield_matches = bitfield_pattern.findall(code)

        # Iterate through the matches and check if they are potential CWE188 vulnerabilities
        for match in union_matches + struct_matches + bitfield_matches:
            # Check if the left and right sides of the assignment are the same type
            left, right = match
            left_type = left.split(' ')[-1].strip(';')
            right_type = right.split(' ')[-1].strip(';')
            if left_type == right_type:
                vulnerability_found = True
                break

        # Return the result of the vulnerability check
        return vulnerability_found
