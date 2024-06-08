import re
from ingest_class import IngestClass

class CWE122Parser(IngestClass):

    def parser(self, code):
        # Regular expressions to match common CWE122 patterns
        dynamic_allocation_pattern = r'\b(?:malloc|calloc|realloc)\s*\('
        free_pattern = r'\bfree\s*\('
        array_access_pattern = r'(\w+)\s*\[\s*(\w+|\d+)\s*\]'
        array_size_pattern = r'(\w+)\s*(?:\[\s*(\w+|\d+)\s*\])?\s*(?:=\s*(?:\w+|\d+))?\s*;'
        array_size_dict = {}

        # Extract array sizes
        for match in re.finditer(array_size_pattern, code):
            array_name = match.group(1)
            array_size = match.group(2)
            if array_size:
                array_size_dict[array_name] = array_size

        # Check for dynamic memory allocation
        if re.search(dynamic_allocation_pattern, code):
            #print("Dynamic memory allocation detected.")
            # Check for free calls
            if re.search(free_pattern, code):
                #print("Free calls detected.")
                # Check for array accesses
                for match in re.finditer(array_access_pattern, code):
                    array_name = match.group(1)
                    if array_name in array_size_dict:
                        array_size = int(array_size_dict[array_name])
                        index = match.group(2)
                        if not index.isdigit():
                            # If the index is not a digit, we can't determine its value statically
                            #print(f"Potential CWE122 vulnerability in array '{array_name}' due to dynamic index.")
                            return True
                        elif int(index) >= array_size:
                            #print(f"Potential CWE122 vulnerability in array '{array_name}' due to out-of-bounds access.")
                            return True
                    else:
                        pass#print(f"Array size not found for array '{array_name}'.")
        return False

if __name__ == '__main__':

    # Example usage:
    c_code_example_1 = """
    #include <stdio.h>
    #include <stdlib.h>

    int main() {
        int *ptr = (int*)malloc(10 * sizeof(int));
        ptr[10] = 5; // Potential heap-based buffer overflow
        free(ptr);
        return 0;
    }
    """

    c_code_example_2 = """
    #include <stdio.h>
    #include <stdlib.h>

    int main() {
        int arr[10];
        for (int i = 0; i < 10; ++i) {
            arr[i] = i; // No potential buffer overflow
        }
        return 0;
    }
    """

    print("Example 1 Result:")
    if CWE122Parser.parser(c_code_example_1):
        print("CWE122 Heap Based Buffer Overflow vulnerability found in the code.")
    else:
        print("No CWE122 Heap Based Buffer Overflow vulnerability found in the code.")

    print("\nExample 2 Result:")
    if CWE122Parser.parser(c_code_example_2):
        print("CWE122 Heap Based Buffer Overflow vulnerability found in the code.")
    else:
        print("No CWE122 Heap Based Buffer Overflow vulnerability found in the code.")
