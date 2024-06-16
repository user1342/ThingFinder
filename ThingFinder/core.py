import argparse
import os
import importlib.util
import tempfile
import shutil
from ghidrabridge.ghidra_bridge import GhidraBridge
from rich.console import Console
from rich.table import Table
from rich.live import Live
import json

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
                             
    parser.add_argument("--output", metavar="OUTPUT_FILE", help="Path to the file to save the results.")
    parser.add_argument("--thing_folder", metavar="PARSER_FOLDER", help="Path to folder container thing finder parser classes. Overides other parser folders.")
              
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

def run(code, binary, output=None, reachable_from_function=None, thing_folder=None):
    console = Console()


    with tempfile.TemporaryDirectory() as code_folder:

        if code:
            if reachable_from_function:
                print("'--reachable_from_function' only supported with '--binary'")
            if not os.path.isdir(code):
                raise Exception(f"The directory '{code}' provided is not a valid directory!")
            
            with console.status("[bold green]Copying files to temporary folder...") as status:
                copy_folder_contents(code, code_folder)

        elif binary:
            with console.status("[bold green]Decompiling binary...") as status:
                bridge = GhidraBridge()
                bridge.decompile_binaries_functions(binary, code_folder)

            if reachable_from_function:
                with console.status("[bold green]Retrieving reachable functions...") as status:
                    reachable_functions = bridge.get_list_of_reachable_functions(binary, reachable_from_function)
                
                reachable_functions = reachable_functions + [reachable_from_function]

                # Loop through files in the directory
                for filename in os.listdir(code_folder):
                    file_path = os.path.join(code_folder, filename)
                    # Check if the filename contains any substring
                    if not any(substring in filename for substring in reachable_functions):
                        # If it doesn't contain any substring, delete the file
                        os.remove(file_path)

        # Loop through all files in the folder
        results = {}
        filtered_results = {}
        
        with Live(Table(), refresh_per_second=1, console=console) as live:

            for root, dirs, files in os.walk(code_folder):
                for filename in files:
                    
                    # Construct the full path to the file
                    file_path = os.path.join(root, filename)
                    # Check if the current item is a file (not a subfolder)

                    if os.path.isfile(file_path):
                        # Open the file and read its contents
                        with open(file_path, 'r') as file:
                            contents = file.read()
                            # Get the directory path of the current script
                            script_dir = os.path.dirname(os.path.abspath(__file__))


                            # Define the folder path relative to the script's location
                            home_dir = os.path.expanduser("~")
                            destination_dir = os.path.join(home_dir, '.ThingFinder_Things')

                            if thing_folder:
                                if os.path.exists(thing_folder):
                                    results[filename] = load_parsers_from_folder(thing_folder, contents)
                                else:
                                    raise Exception(f"Thing folder {thing_folder} provided, however, it does not exist.")
                            else:

                                try:
                                    results[filename] = load_parsers_from_folder(destination_dir, contents)
                                except:
                                    try:
                                        # thing files may be stored at home after install
                                        if filename not in results or len(results[filename]) == 0:
                                            folder_path = os.path.join(script_dir, "things")
                                            results[filename] = load_parsers_from_folder(folder_path, contents)
                                    except:
                                        continue
                                
                            filtered_results = {key: value for key, value in results.items() if value}
                            if not len(filtered_results) == 0:
                                
                                # Create a table for the output
                                table = Table(title="'Things' Found'")
                                table.add_column("Location", style="bold")
                                table.add_column("Thing", style="bold")

                                for filename, value in filtered_results.items():
                                    highlighted_filename = f"[bold green]{filename}[/bold green]"  # Highlight filename
                                    thing_names = [thing for thing, cwe_exists in value.items() if cwe_exists]  # Get CWE names
                                    thing_str = ', '.join(thing_names) if thing_names else ""  # Join CWE names
                                    table.add_row(highlighted_filename, thing_str)
                                    live.update(table)

                        
                 
        if len(filtered_results) == 0:
            console.log("No things found...")

        # Save the results to a file if --output is specified
        if output:
            with open(output, 'w') as output_file:
                json.dump(filtered_results, output_file, indent=4)
            console.log(f"Results saved to {output}")

    return filtered_results

def main():
    """
    Main function to execute the program.
    """
    args = parse_args()

    output = None
    if args.output:
        output = args.output

    reachable_from_function = None
    if args.reachable_from_function:
        reachable_from_function = args.reachable_from_function

    code = None
    if args.code:
        code = args.code

    binary = None
    if args.binary:
        binary = args.binary


    thing_folder = None
    if args.thing_folder:
        thing_folder = args.thing_folder
    
    run(code, binary, output, reachable_from_function, thing_folder)

if __name__ == "__main__":
    main()
