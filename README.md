# Tools

**Overview**

This repository contains miscellaneous generic Python tools

**Python Library Validation: lib_validate.py**

Validates the Python development environment by checking the Pythong version and import path.
Also Checks to ensure that all imported libraries required the modules in brcdapi and brcddb are in the Python path.

*Background*

The most common problem I ran into helping customers getting their scripts running was finding the libraries. I wrote
this script to help aid in determining why import statements were failing. Common problems that this script tries to
help identify, are:

* Imported libraries are imported from a different path than the customer thought.
* Imported libraries cannot be found
* Imported libraries are not executable
* Imported libraries import additional libraries the customer did not install

I thought about using modulefinder but I wanted to know all the library paths an import is found in. I also wanted to
read the file attributes so I cn report if the library was executable. It was easier to read the file attributes than
figuring out all the exceptions and reading the file attributes gave me more information.

I ended up plowing my way through it by recursively reading each file and looking for the import statements. Although
unlikely, it's possible to have executable rights but not read access so I attempt to import each import module even if
I couldn't read it.

*Description*

Accepts a Python module, or list of Python modules. Each module is read to extract the import statements. Each module
associated with an import statement is read. If the module is a folder then each module in the folder is read. This is
done recursively so that all required import files are determined.

The file paths and attributes are read and an import of each module to import is attempted so as to generate a report
that contains:

* A list of library search paths
* The operating system, version, and release number
* File attributes associated with each module
* Articulated list of where each imported module was imported from
* List of individual success or failure for each import
* List of all paths where an imported module can be found

