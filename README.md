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

  -c YARA_FILE_PATH, --consolidate=YARA_FILE_PATH
                        File path for consolidated YARA file
                        
  -m, --modify          Modify the file to rename duplicate rules
  
  -i YARA_INDEX_PATH, --index=YARA_INDEX_PATH
                        Create and index of YARA files
                        
  -b BASE_FOLDER_PATH, --BaseDirectory=BASE_FOLDER_PATH
                        Base folder to mark as current directory ./
                        
  -s, --subdirectories  Recurse into subdirectories
  
  
Remove duplicates example:

                  YARA_Duplicate_Rules.py -d "C:\YARAFolder" -r


Create index for a directory example:

                  YARA_Duplicate_Rules.py -d C:\YARA\rules-master\email -i C:\YARA\rules-master\email_index_new.yar -b rules-master

                  
Create index for subdirectories example:

                  YARA_Duplicate_Rules.py -d C:\YARA\rules-master -i C:\YARA\rules-master\index_new.yar -b rules-master -s              