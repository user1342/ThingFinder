<p align="center">
    <img width=100% src="banner.png">
  </a>
</p>
<p align="center"> 🔦 Finding ‘things’ in binaries and source code 🔎 </p>

<div align="center">

![GitHub contributors](https://img.shields.io/github/contributors/user1342/ThingFinder)
![GitHub Repo stars](https://img.shields.io/github/stars/user1342/ThingFinder?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/user1342/ThingFinder?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/user1342/ThingFinder)
<br>

</div>

ThingFinder is a python tool designed to facilitate searching and analysing code, whether it's source code or compiled binary executables. It provides a modular interface for adding new parsers for identifying new 'things' in that code, be it vulnerabilities, malware, or other patterns. 


# ⚙️ Setup


## System Requirements
When using ThingFinder for binary analysis it utilises [GhidraBridge](https://github.com/user1342/GhidraBridge) which requires [Ghidra](https://ghidra-sre.org/) to be installed and accessible. Ensure that `analyzeHeadless` is available in your environment.

**ThingFinder has been tested on Windows 11; however, it should be compatible with Unix and other systems.**

## Install
```
pip install -r requirements.txt
```

ThingFinder can then be installed using the `./setup.py` script as below:

```
python -m pip install .
```

# 🏃 Running
## For source code analysis

```bash
ThingFinder --code <path-to-code-folder>
```
## For binary analysis
ThingFinder uses [GhidraBridge](https://github.com/user1342/GhidraBridge) to decompile the binary and uses the Ghidra CFG to identify which functions may be reachable from anouther function (allowing you to provide the ```--reachable_from_function``` argument to limit your search to such functions.

```bash
ThingFinder--binary <path-to-binary> [--reachable_from_function <function-name>]
```

# 🔨 Building 'things' parsers
ThingFinder is modular, and all parsers present in the ```things``` folder when built will be used on target binaries and code when run. These parsers may be to identify vulnerabilities, interesting code elements, etc.

To write your own thing parser follow the below:
1) Create a file in the ```things``` folder, ending in ```_parser.py```. Ensure to have a good name for the rest of the file as that will be used to identify what was found. 
2) Create a class that inherits from the ```IngestClass``` class.
3) Ensure your class has a ```parser``` function that takes ```self``` and ```code```.
4) Your function should then take the code and review it for what your parser is looking for. If it's been found it should return ```True``` else ```False```.

An example of this can be seen below (named ```passwords_parser.py```):

```python
try:
    from ThingFinder.ingest_class import IngestClass
except:
   from ingest_class import IngestClass 

class SimplePasswordFinder(IngestClass):

    def parser(self, code):
        if "password" in code:
            return True
        else:
            return False
```

# 📦 Example output
The below is an example of running ThingFinder with the ```cwe122_parser.py``` parser against a portion of the [Juliet vulnerable code dataset](https://samate.nist.gov/SARD/test-suites/112).

```bash
ThingFinder.exe --code "2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3\C\testcases\CWE122_Heap_Based_Buffer_Overflow\s11"
```

```
                                'Things' Found'
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━┓
┃ Location                                                            ┃ Thing  ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━┩
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_01.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_02.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_03.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_04.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_05.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_06.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_07.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_08.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_09.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_10.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_11.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_12.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_13.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_14.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_15.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_16.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_17.c │ CWE122 │
│ CWE122_Heap_Based_Buffer_Overflow__wchar_t_type_overrun_memcpy_18.c │ CWE122 │
└─────────────────────────────────────────────────────────────────────┴────────┘
```

# ⚖️ Code of Conduct
ThingFinder follows the Contributor Covenant Code of Conduct. Please make sure to review and adhere to this code of conduct when contributing to ThingFinder.

# 🐛 Bug Reports and Feature Requests
If you encounter a bug or have a suggestion for a new feature, please open an issue in the GitHub repository. Please provide as much detail as possible, including steps to reproduce the issue or a clear description of the proposed feature. Your feedback is valuable and will help improve ThingFinder for everyone.

# 📜 License

[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)

# ⭐ Thanks
The name and high-level idea for ThingFinder came from the tool [FlawFinder](https://github.com/david-a-wheeler/flawfinder) check it out!
