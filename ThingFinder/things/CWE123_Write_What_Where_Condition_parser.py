import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE123Parser(IngestClass):

    def parser(self, code):
        # Define regular expressions for pattern matching
        linked_list_pattern = r'struct\s+_linkedList\s*\{.*\}\s*;'
        bad_struct_pattern = r'struct\s+_badStruct\s*\{.*\}\s*;'
        linked_list_ptr_pattern = r'struct\s+_linkedList\s*\*\s*'
        fgets_pattern = r'fgets\(\s*\(\s*char\*\s*,\s*int\s*,\s*FILE\s*\*\s*\)\s*\)'

        # Find the relevant patterns in the code
        linked_list_found = bool(re.search(linked_list_pattern, code))
        bad_struct_found = bool(re.search(bad_struct_pattern, code))
        linked_list_ptr_found = bool(re.search(linked_list_ptr_pattern, code))
        fgets_found = bool(re.search(fgets_pattern, code))

        # Check if all necessary patterns are present
        if linked_list_found and bad_struct_found and linked_list_ptr_found and fgets_found:
            return True
        else:
            return False
