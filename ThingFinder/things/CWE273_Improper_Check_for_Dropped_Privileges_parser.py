import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 
   
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
