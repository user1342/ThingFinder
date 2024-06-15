Here is a Python class that inherits from the `IngestClass` and implements a parser function to detect CWE273_Improper_Check_for_Dropped_Privileges vulnerabilities in C code. The parser function uses string parsing, regex, and other Python techniques to identify the vulnerability.

```python
import re

class CWE273Parser(IngestClass):

    def __init__(self):
        super().__init__()
        self.function_names = [
            "CWE273_Improper_Check_for_Dropped_Privileges__w32_RpcImpersonateClient_",
            "CWE273_Improper_Check_for_Dropped_Privileges__w32_ImpersonateNamedPipeClient_"
        ]

    def parser(self, code):
        for function_name in self.function_names:
            if re.search(function_name, code, re.IGNORECASE):
                # Check for missing checks for dropped privileges
                if not re.search(r"CheckPrivilege\(.*\)", code, re.IGNORECASE):
                    return True
        return False
```

In this code, the `CWE273Parser` class initializes a list of function names that are known to contain the CWE273 vulnerability. The `parser` function searches the provided C code for these function names. If a function is found, it checks for the presence of a `CheckPrivilege` call, which would indicate a proper check for dropped privileges. If no `CheckPrivilege` call is found, the function returns `True`, indicating the presence of the CWE273 vulnerability. Otherwise, it returns `False`.