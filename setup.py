from setuptools import setup, find_packages

setup(
    name='ThingFinder',
    version='1.0.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'ThingFinder = ThingFinder.core:main'
        ]
    },
    author='James Stevenson',
    description='A tool for finding things in binarys and source code.'
)
