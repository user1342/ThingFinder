import re
from ingest_class import IngestClass


class ProcessControlChecker(IngestClass):

    def parser(self, code):
        """
        Identifies CWE-114 Process Control vulnerabilities in C code.
        
        CWE-114: Process Control vulnerabilities occur when dynamic link libraries (DLLs)
        are loaded using a relative path instead of a full path, which can be exploited
        by attackers to load malicious libraries.
        
        This method uses regex and string parsing techniques to identify such vulnerabilities
        in the given C code.
        
        Args:
            code (str): The C code to analyze.
        
        Returns:
            bool: True if a vulnerability is present, False otherwise.
        """
        # Check for patterns where libraries are loaded with just the filename (potential vulnerability)
        # The patterns to look for are strings like:
        # wcscpy(data, L"winsrv.dll");
        # strcpy(data, "winsrv.dll");
        # LoadLibraryA(data);

        # Regex pattern to match the vulnerable library loading code
        vulnerable_pattern = re.compile(
            r'(wcscpy|strcpy)\s*\(\s*.*\s*,\s*L?"[a-zA-Z0-9_.]+\.dll"\s*\)', re.IGNORECASE
        )
        
        # Regex pattern to match the safe library loading code (full path)
        safe_pattern = re.compile(
            r'(wcscpy|strcpy)\s*\(\s*.*\s*,\s*L?"[a-zA-Z]:\\.*\\[a-zA-Z0-9_.]+\.dll"\s*\)', re.IGNORECASE
        )

        # Check if the code contains any vulnerable pattern
        if vulnerable_pattern.search(code) and not safe_pattern.search(code):
            return True
        
        return False

# Example usage:
if __name__ == "__main__":
    checker = ProcessControlChecker()
    
    # Example C code containing CWE-114 vulnerabilities
    code_with_vulnerability = """
    /* FLAW: Specify just the file name for the library, not the full path */
    wcscpy(data, L"winsrv.dll");
    """
    
    code_without_vulnerability = """
    /* FIX: Specify the full pathname for the library */
    wcscpy(data, L"C:\\Windows\\System32\\winsrv.dll");
    """
    
    print(checker.parser(code_with_vulnerability))  # Expected output: True
    print(checker.parser(code_without_vulnerability))  # Expected output: False
