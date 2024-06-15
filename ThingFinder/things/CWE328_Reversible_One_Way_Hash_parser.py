Here is a Python class that inherits from the `IngestClass` and implements a parser function to detect CWE328_Reversible_One_Way_Hash vulnerabilities in C code. The parser function uses string parsing, regex, and other techniques available in Python to identify the vulnerabilities.

```python
import re

class CWE328Parser(IngestClass):

    def parser(self, code):
        # Initialize a set to store the hashing functions we are looking for
        hashing_functions = {"MD2", "MD5", "SHA1"}

        # Use regex to find the function calls in the code
        function_calls = re.findall(r'(CWE328_[A-Z0-9_]+)\(\);', code, re.IGNORECASE)

        # Iterate through the function calls and check if they are hashing functions
        for function in function_calls:
            if function.startswith("CWE328_") and function[7:] in hashing_functions:
                return True

        # If no vulnerable function calls are found, return False
        return False
```

This code works by first defining a set of hashing functions we are looking for. Then, it uses regex to find function calls in the code. If a function call matches one of the hashing functions, the function returns True, indicating the presence of the CWE328_Reversible_One_Way_Hash vulnerability. If no vulnerable function calls are found, the function returns False.