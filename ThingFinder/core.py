import argparse
import os
import importlib.util
import tempfile
import shutil
from ghidrabridge.ghidra_bridge import GhidraBridge
from pprint import pprint
from rich.console import Console
from rich.table import Table
from rich.live import Live


def parse_args():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(description="Process C code or binary files.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--code", metavar="CODE_FOLDER", help="Path to the folder containing C code.")
    group.add_argument("--binary", metavar="BINARY_FILE", help="Path to the binary file.")
    
    # Adding --reachable_from_function only if --binary is provided
    parser.add_argument("--reachable_from_function", metavar="FUNCTION_NAME", 
                        help="Specify a function name to review only reachable functions "
                             "(valid only if --binary is provided).", nargs='?')
    return parser.parse_args()


def copy_folder_contents(source_folder, destination_folder):
    """
    Copy the contents of one folder to another.
    """
    # Check if the source folder exists
    if not os.path.exists(source_folder):
        print(f"Source folder '{source_folder}' does not exist.")
        return
    
    # Create the destination folder if it doesn't exist
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)
    
    # Iterate through all files and subdirectories in the source folder
    for item in os.listdir(source_folder):
        source_item = os.path.join(source_folder, item)
        destination_item = os.path.join(destination_folder, item)
        
        # If it's a file, copy it to the destination folder
        if os.path.isfile(source_item):
            shutil.copy2(source_item, destination_item)
        # If it's a directory, recursively copy its contents
        elif os.path.isdir(source_item):
            copy_folder_contents(source_item, destination_item)
        else:
            print(f"Ignoring '{source_item}' because it's neither a file nor a directory.")


def load_parsers_from_folder(folder_path, code):
    """
    Load parsers from Python files in a folder and execute them.
    """
    results = {}
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith('.py') and "parser" in file:
                module_name = file[:-3]
                module_path = os.path.join(root, file)
                spec = importlib.util.spec_from_file_location(module_name, module_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                for name in dir(module):
                    if not "IngestClass" in name:
                        obj = getattr(module, name)
                        try:
                            parser_instance = obj()
                        except:
                            continue
                        if hasattr(parser_instance, 'parser'):
                            result = bool(parser_instance.parser(code=code))

                            name = file.strip("_parser.py").upper()
                            if result:
                                if file in results:
                                    results[name] = results[name] + result
                                else:
                                    results[name] = result
                        else:
                            raise AttributeError(f"Class {name} in {module_path} does not have a 'parse' method.")
    return results
                       

def main():
    """
    Main function to execute the program.
    """
    args = parse_args()
    console = Console()


    with tempfile.TemporaryDirectory() as code_folder:

        if args.code:
            if args.reachable_from_function:
                print("'--reachable_from_function' only supported with '--binary'")
            if not os.path.isdir(args.code):
                raise Exception(f"The directory '{args.code}' provided is not a valid directory!")
            
            with console.status("[bold green]Copying files to temporery folder...") as status:
                copy_folder_contents(args.code, code_folder)

        elif args.binary:
            with console.status("[bold green]Decompiling binary...") as status:
                bridge = GhidraBridge()
                bridge.decompile_binaries_functions(args.binary, code_folder)

            if args.reachable_from_function:
                with console.status("[bold green]Retrieving reachable functions...") as status:
                    reachable_functions = bridge.get_list_of_reachable_functions(args.binary, args.reachable_from_function)
                
                reachable_functions = reachable_functions + [args.reachable_from_function]

                # Loop through files in the directory
                for filename in os.listdir(code_folder):
                    file_path = os.path.join(code_folder, filename)
                    # Check if the filename contains any substring
                    if not any(substring in filename for substring in reachable_functions):
                        # If it doesn't contain any substring, delete the file
                        os.remove(file_path)

        # Loop through all files in the folder
        results = {}
        with Live(Table(), refresh_per_second=4, console=console) as live:

            for filename in os.listdir(code_folder):
                # Construct the full path to the file
                file_path = os.path.join(code_folder, filename)
                
                # Check if the current item is a file (not a subfolder)
                if os.path.isfile(file_path):
                    # Open the file and read its contents
                    with open(file_path, 'r') as file:
                        contents = file.read()
                        # Get the directory path of the current script
                        script_dir = os.path.dirname(os.path.abspath(__file__))

                        # Define the folder path relative to the script's location
                        folder_path = os.path.join(script_dir, "things")
                        results[filename] = load_parsers_from_folder(folder_path, contents)

                        filtered_results = {key: value for key, value in results.items() if value}
                        # Create a table for the output
                        table = Table(title="'Things' Found'")
                        table.add_column("Location", style="bold")
                        table.add_column("Thing", style="bold")

                        console.clear()

                        for filename, value in filtered_results.items():
                            highlighted_filename = f"[bold green]{filename}[/bold green]"  # Highlight filename
                            thing_names = [thing for thing, cwe_exists in value.items() if cwe_exists]  # Get CWE names
                            thing_str = ', '.join(thing_names) if thing_names else ""  # Join CWE names
                            table.add_row(highlighted_filename, thing_str)
                            live.update(table)


if __name__ == "__main__":
    main()
