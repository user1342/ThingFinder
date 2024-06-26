import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE122Detector(IngestClass):

    def parser(self, code):
        # Initialize variables
        buffer_overflow = False
        buffer_size = None
        data_type = None

        # Find the relevant code block
        pattern = r'void\s+(\w+)\s*\(\)'
        match = re.search(pattern, code, re.MULTILINE)
        if match:
            function_name = match.group(1)

            # Check if the function contains malloc and new with placement
            pattern = r'malloc\(\s*(\d+)\s*\)'
            malloc_match = re.findall(pattern, code, re.MULTILINE)
            if malloc_match:
                buffer_size = int(malloc_match[0])

            pattern = r'new\s*\(\s*(\w+)\s*\s*\(\s*(\w+)\s*\s*(\d+)\s*\)\s*\)'
            new_match = re.findall(pattern, code, re.MULTILINE)
            if new_match:
                data_type = new_match[0][1]

            # Check if the buffer size is less than the size of the data type
            if buffer_size and data_type:
                if buffer_size < self._get_size_of_type(data_type):
                    buffer_overflow = True

        return buffer_overflow

    def _get_size_of_type(self, data_type):
        # Get the size of the data type
        # You can use a dictionary or a function to map C data types to their sizes
        # For simplicity, this example uses a hardcoded mapping
        data_type_sizes = {
            'char': 1,
            'int': 4,
            'float': 4,
            'double': 8,
            'struct': 8,  # Assuming an average struct size of 8 bytes
            'TwoIntsClass': 8  # Assuming a TwoIntsClass size of 8 bytes
        }
        return data_type_sizes.get(data_type, 8)  # Return 8 bytes as a default size if the data type is not found