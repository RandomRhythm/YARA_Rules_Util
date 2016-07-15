# YARA_Duplicate_Rules
YARA duplicate rule detection and removal


This script was written to deal with YARA error “duplicated identifier” in Cuckoo sandbox:

ERROR: Unable to match Yara signatures: /path/to/file.yar(85): duplicated identifier "RuleName" 


Parameters are optional. If you don’t provide the directory path the current directory is used. 

Options:

  -h, --help            show this help message and exit
  
  -r, --remove          Remove duplicate rules
  
  -d YARA_DIRECTORY_PATH, --directory=YARA_DIRECTORY_PATH
                      (Folder path to directory containing YARA files)


Example:

                  YARA_Duplicate_Rules.py -d "C:\YARAFolder" -r
