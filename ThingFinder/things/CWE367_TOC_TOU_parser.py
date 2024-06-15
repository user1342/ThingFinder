import re
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class CWE367_TOC_TOU_IngestClass(IngestClass):

    def parser(self, code):
        # Initialize a variable to store the result
        result = False

        # Use regex to find function calls that might be vulnerable
        vulnerable_function_pattern = r'(CWE367_TOC_TOU__[a-zA-Z0-9_]+)(\s*\()'
        matches = re.findall(vulnerable_function_pattern, code)

        # Iterate through the matches and check if the function is a bad function
        for match in matches:
            function_name = match[0]
            if function_name in ['CWE367_TOC_TOU__access_01_bad', 'CWE367_TOC_TOU__access_02_bad', 'CWE367_TOC_TOU__access_03_bad', 'CWE367_TOC_TOU__access_04_bad', 'CWE367_TOC_TOU__access_05_bad', 'CWE367_TOC_TOU__access_06_bad', 'CWE367_TOC_TOU__access_07_bad', 'CWE367_TOC_TOU__access_08_bad', 'CWE367_TOC_TOU__access_09_bad', 'CWE367_TOC_TOU__access_10_bad', 'CWE367_TOC_TOU__access_11_bad', 'CWE367_TOC_TOU__access_12_bad', 'CWE367_TOC_TOU__access_13_bad', 'CWE367_TOC_TOU__access_14_bad', 'CWE367_TOC_TOU__access_15_bad', 'CWE367_TOC_TOU__access_16_bad', 'CWE367_TOC_TOU__access_17_bad', 'CWE367_TOC_TOU__access_18_bad', 'CWE367_TOC_TOU__stat_01_bad', 'CWE367_TOC_TOU__stat_02_bad', 'CWE367_TOC_TOU__stat_03_bad', 'CWE367_TOC_TOU__stat_04_bad', 'CWE367_TOC_TOU__stat_05_bad', 'CWE367_TOC_TOU__stat_06_bad', 'CWE367_TOC_TOU__stat_07_bad', 'CWE367_TOC_TOU__stat_08_bad', 'CWE367_TOC_TOU__stat_09_bad', 'CWE367_TOC_TOU__stat_10_bad', 'CWE367_TOC_TOU__stat_11_bad', 'CWE367_TOC_TOU__stat_12_bad', 'CWE367_TOC_TOU__stat_13_bad', 'CWE367_TOC_TOU__stat_14_bad', 'CWE367_TOC_TOU__stat_15_bad', 'CWE367_TOC_TOU__stat_16_bad', 'CWE367_TOC_TOU__stat_17_bad', 'CWE367_TOC_TOU__stat_18_bad']:
                result = True
                break

        # Return the result
        return result
