<p align="center">
    <img width=100% src="banner.png">
  </a>
</p>
<p align="center"> 🔦 Finding ‘things’ in binaries and C source 🔎 </p>

<div align="center">

![GitHub contributors](https://img.shields.io/github/contributors/user1342/ThingFinder)
![GitHub Repo stars](https://img.shields.io/github/stars/user1342/ThingFinder?style=social)
![GitHub watchers](https://img.shields.io/github/watchers/user1342/ThingFinder?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/user1342/ThingFinder)
<br>

</div>

# ⚙️ Setup
```
pip install -r requirements.txt
```

ThingFinder can then be installed using the `./setup.py` script as below:

```
python -m pip install .
```

# 🏃 Running
To use ThingFinder:

- Provide the path to either a folder containing C code (--code) or a binary file (--binary).
- Optionally, specify a function name to review only reachable functions (valid only if --binary is provided).
- Run ThingFinder using the appropriate command:
- For C code: ```ThingFinder --code <path-to-code-folder>```
- For binary: ```ThingFinder--binary <path-to-binary> [--reachable_from_function <function-name>]```


# ⚖️ Code of Conduct
ThingFinder follows the Contributor Covenant Code of Conduct. Please make sure to review and adhere to this code of conduct when contributing to ThingFinder.

# 🐛 Bug Reports and Feature Requests
If you encounter a bug or have a suggestion for a new feature, please open an issue in the GitHub repository. Please provide as much detail as possible, including steps to reproduce the issue or a clear description of the proposed feature. Your feedback is valuable and will help improve ThingFinder for everyone.

# 📜 License

[GNU General Public License v3.0](https://choosealicense.com/licenses/gpl-3.0/)
