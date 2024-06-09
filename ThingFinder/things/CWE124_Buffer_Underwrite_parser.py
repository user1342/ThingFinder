import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE124Parser(IngestClass):

    def parser(self, code):
        # Initialize a flag to store the result
        result = False

        # Find all function definitions in the code
        function_defs = re.findall(r'void\s*(\w+)\s*\((.*)\)\s*{.*}', code, re.DOTALL)

        # Iterate through each function definition
        for function_name, function_args in function_defs:
            # Check if the function name matches any known bad functions
            if function_name in ['badSink', 'CWE124_Buffer_Underwrite__wchar_t_declare_memcpy_73a.badSink']:
                # Find the data pointer assignment in the function body
                data_assignment = re.search(r'wchar_t\s*(\*data)\s*=\s*(\w+)\s*-\s*(\d+);', function_args, re.DOTALL)

                # If a data pointer assignment is found, check if it's before the allocated memory buffer
                if data_assignment:
                    # Calculate the size of the allocated memory buffer
                    buffer_size = int(re.search(r'wchar_t\s+(\d+)\s*[\w\s]*;', function_args, re.DOTALL).group(1))
                    # Check if the data pointer is before the allocated memory buffer
                    if int(data_assignment.group(3)) < buffer_size:
                        result = True

        return result
