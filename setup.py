import os
import shutil
from setuptools import setup, find_packages
from distutils.command.install import install as DistutilsInstall

class CustomInstall(DistutilsInstall):
    def run(self):
        # Run the default installation steps
        DistutilsInstall.run(self)
        # Custom post-installation steps
        self.copy_files()

    def copy_files(self):
        # Get the user's home directory
        home_dir = os.path.expanduser("~")
        
        # Specify source directory
        source_dir = os.path.join('ThingFinder', 'things')

        # Try default destination directory
        destination_dir = os.path.join(home_dir, '.ThingFinder_Things')

        # Try alternate destination directory if default directory exists

        if os.path.exists(destination_dir):
            try:
                shutil.rmtree(destination_dir)
                print(f"Folder '{destination_dir}' and its contents successfully removed.")
            except OSError as e:
                print(f"Error: {destination_dir} : {e.strerror}")
        else:
            print(f"Folder '{destination_dir}' does not exist.")

        try:
            # Create the destination directory if it doesn't exist
            os.makedirs(destination_dir, exist_ok=True)
        except:
            pass


        # Copy files
        print("Copying files from {} to {}".format(source_dir, destination_dir))
        print("from "+source_dir)
        files = os.listdir(source_dir)

        # Iterate over each file and copy it to the destination folder
        for file_name in files:
            if ".py" in file_name:
                source_file = os.path.join(source_dir, file_name)
                destination_file = os.path.join(destination_dir, file_name)
                shutil.copy(source_file, destination_file)

setup(
    name='ThingFinder',
    version='1.0.2',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'ThingFinder = ThingFinder.core:main'
        ]
    },
    author='James Stevenson',
    description='A tool for finding things in binaries and source code.',
    cmdclass={'install': CustomInstall},  # Custom install class
)
