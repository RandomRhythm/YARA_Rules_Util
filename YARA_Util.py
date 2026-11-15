#This script can identify and remove duplicate rules (based on rule name) from YARA files contained within a directory.
#Duplicate rules are logged to duplicate.log in the current directory.
#Rule names are echoed to standard out.
#Be sure to backup your data before using the remove option.

#Copyright (c) 2020 Ryan Boyle randomrhythm@rhythmengineering.com.
#All rights reserved.

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.


import os
from optparse import OptionParser
import sys
import datetime
import re

#Matches a rule declaration with optional private/global modifiers and leading whitespace.
#Only the identifier is captured, so tags, comments and braces on the same line are ignored.
reRuleDecl = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)")

def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Find duplicate YARA rules in a directory")
    parser.add_option("-r", "--remove", help="Remove duplicate rules", action="store_true")
    parser.add_option("-d", "--directory", action="store", default=None, dest="YARA_Directory_Path",
                      help="Folder path to directory containing YARA files")
    parser.add_option("-c", "--consolidate", action="store", default=None, dest="YARA_File_Path",
                      help="File path for consolidated YARA file")
    parser.add_option("-m", "--modify", help="Modify the file to rename duplicate rules", action="store_true")
    parser.add_option("-i", "--index", action="store", default=None, dest="YARA_Index_Path",
                      help="Create an index of YARA files") 
    parser.add_option("-t", "--type", action="store", default=None, dest="YARA_Index_Type",
                      help="Index YARA files based on parent folder match.") 
    parser.add_option("-b", "--BaseDirectory", action="store", default=None, dest="Base_Folder_Path",
                      help="Base folder to mark as current directory ./") 
    parser.add_option("-s", "--subdirectories", help="Recurse into subdirectories", action="store_true")
    parser.add_option("-v", "--verboselog", help="log all rules and the associated file", action="store_true")
    return parser
    
def ProcessRule(lstRuleFile, strYARApath, strOutPath):
  strYARAout = ""
  strLogOut = ""
  boolExcludeLine = False
  boolOverwrite = False
  if strOutPath == "":
    strOutPath = strYARApath
  for strRuleLine in lstRuleFile:
    strRuleOut = strRuleLine
    ruleMatch = reRuleDecl.match(strRuleLine)
    if ruleMatch:
      strRuleName = ruleMatch.group("name")
      print (strRuleName)
      if boolLogging == True:
        logToFile(strCurrentDirectory + "/all_rules.csv",strRuleName + "," + strYARApath + "\n", False, "a")
      if strRuleName in dictRuleName:
        #print "duplicate rule in file " + strYARApath + " : " + strRuleName
        strLogOut = strLogOut + "Duplicate rule " + "\n" + strRuleName + " in " + dictRuleName[strRuleName]  + "\n" + strRuleName + " in " + strYARApath + "\n"
        if boolRename == False:
            boolExcludeLine = True
            
            if boolRemoveDuplicate == True:
              boolOverwrite = True
              strLogOut = strLogOut + "Removed rule " + strRuleName + " from " + strYARApath + "\n"
        else:
            intCount = 1
            while strRuleName + "_" + str(intCount) in dictRuleName:
                intCount += 1
            strNewName = strRuleName + "_" + str(intCount)
            #replace only the rule identifier, not other text on the line
            strRuleOut = strRuleLine[:ruleMatch.start("name")] + strNewName + strRuleLine[ruleMatch.end("name"):]
            dictRuleName[strNewName] = strYARApath
            strLogOut = strLogOut + "Renamed " + strRuleName + " to " + strNewName + " from " + strYARApath + "\n"
            strYARAout = strYARAout + strRuleOut
            boolOverwrite = True
      else:
        dictRuleName[strRuleName] = strYARApath
        strYARAout = strYARAout + strRuleOut
        boolExcludeLine = False
    elif boolExcludeLine == False:
      strYARAout = strYARAout + strRuleLine
  if strOutPath != strYARApath:
    if strYARAout.strip() != "": #nothing new to add, so don't pad the combined file with blank lines
      strYARAout = strYARAout + "\n" #extra new line to separate rules in combined file
      logToFile(strOutPath,strYARAout, False, "a", "")
  elif boolOverwrite == True:
    logToFile(strYARApath,strYARAout, True, "w", "")
  if len(strLogOut) > 1:
    strLogOut = "-------------" + "\n" + strLogOut  
  logToFile(strCurrentDirectory + "/duplicate.log",strLogOut, False, "a")
  
def logToFile(strfilePathOut, strDataToLog, boolDeleteFile, strWriteMode, strNewline=None):
    #UTF-8 with surrogateescape so bytes that aren't valid UTF-8 are written back unchanged.
    #Pass strNewline="" when writing rule content to keep the original line endings.
    with open(strfilePathOut, strWriteMode, encoding="utf-8", errors="surrogateescape", newline=strNewline) as target:
      if boolDeleteFile == True:
        target.truncate()
      target.write(strDataToLog)


def createIndexFile(boolNew, strFilePath, yaraPath, baseDir): # if index creation is not working on Windows check that you are escaping backslashes
  includePath = ""
  if boolNew == True:
    logToFile(strFilePath, "/*\n", True, "w") #start a fresh index each run
    logToFile(strFilePath, "Generated by YARA_Rules_Util\n", False, "a")
    logToFile(strFilePath, "On " + str(datetime.date.today()) + "\n", False, "a")
    logToFile(strFilePath, "*/\n", False, "a")
  #Split on both separators since Windows paths built here can mix \ and /
  arrayPath = re.split(r"[\\/]", yaraPath)
  #Find the base folder among the directory parts (searching from the deepest up).
  #If found, make the include relative to it; otherwise use the full file path.
  intBaseIndex = -1
  if baseDir != "":
    for i in range(len(arrayPath) - 2, -1, -1):
      if arrayPath[i] == baseDir:
        intBaseIndex = i
        break
  if intBaseIndex != -1:
    includePath = "./" + "/".join(arrayPath[intBaseIndex + 1:])
  else:
    includePath = yaraPath
  includeStatement = "include \"" + includePath + "\""
  logToFile(strFilePath, includeStatement + "\n", False, "a")

def fast_scandir(dirname): #https://stackoverflow.com/questions/973473/getting-a-list-of-all-subdirectories-in-the-current-directory/38245063
    subfolders= [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(subfolders):
        subfolders.extend(fast_scandir(dirname))
    return subfolders

boolRemoveDuplicate = False
boolRename = False
boolRecurse = False
boolLogging = False
folderMatch = ""
indexPath = ""
outputPath = ""
baseDirectory = ""
dictExclude = {"deprecated", "index.yar", "_index", "index_"}
strCurrentDirectory = os.getcwd()
strYARADirectory = os.getcwd()
parser = build_cli_parser()
opts, args = parser.parse_args(sys.argv[1:])
if opts.remove:
  boolRemoveDuplicate = True
if opts.subdirectories:  
  boolRecurse = True
  print("recusing subdirectories")
if opts.verboselog:
  boolLogging = True
if opts.YARA_Index_Path:
  indexPath = opts.YARA_Index_Path
  print("creating index file: " + indexPath)
  boolNewIndex = True
if opts.YARA_Index_Type:
  folderMatch = opts.YARA_Index_Type
if opts.Base_Folder_Path:
  baseDirectory = opts.Base_Folder_Path
if opts.YARA_Directory_Path:
  strYARADirectory = opts.YARA_Directory_Path
else:
  print ("No directory provided, using current directory")
if opts.modify:
  boolRename = True
if opts.YARA_File_Path:
  outputPath = opts.YARA_File_Path
dictRuleName = dict()
#Output files are never scanned as input
setOutputFiles = set()
for strOut in (outputPath, indexPath):
  if strOut != "":
    setOutputFiles.add(os.path.normcase(os.path.abspath(strOut)))
#If the consolidated file already exists, load its rule names so this run only
#appends rules that aren't already in it. The file itself is not modified.
if outputPath != "" and os.path.isfile(outputPath):
  with open(outputPath, encoding="utf-8", errors="surrogateescape", newline="") as f:
    for strLine in f:
      ruleMatch = reRuleDecl.match(strLine)
      if ruleMatch and ruleMatch.group("name") not in dictRuleName:
        dictRuleName[ruleMatch.group("name")] = outputPath
  print("Loaded " + str(len(dictRuleName)) + " existing rule names from " + outputPath)
print (strYARADirectory)
logToFile(strCurrentDirectory + "/duplicate.log","Started " + str(datetime.datetime.now()) + "\n", False, "a")

if boolRecurse == True:
  parentDir = fast_scandir(strYARADirectory)
  parentDir.append(strYARADirectory)
  parentDir.sort()
else:
  parentDir = {strYARADirectory}
print(parentDir)
for scanDirs in parentDir:
  for i in os.listdir(scanDirs):
    if i.endswith(".yar") or i.endswith(".yara"):
      if os.path.normcase(os.path.abspath(scanDirs + '/' + i)) in setOutputFiles: #don't read our own output
        continue
      if outputPath != '' and folderMatch != '': #File path for consolidated YARA file and folderMatch file type both provided
        if not scanDirs.endswith(folderMatch): # Not the file type specified so move to next file
          continue
      if indexPath == "":
        print (i)
        #newline="" keeps CRLF/LF as-is so rewritten files keep their line endings
        with open(scanDirs + '/' + i, encoding="utf-8", errors="surrogateescape", newline="") as f:
          lines = f.readlines()
          ProcessRule(lines, scanDirs + '/' + i, outputPath)
      else: #create index
        boolIndexExclude = False
        for excludeItem in dictExclude:
          if excludeItem in scanDirs + '/' + i:
            boolIndexExclude = True
        if folderMatch != "" and not scanDirs.endswith(folderMatch):
          boolIndexExclude = True
        if boolIndexExclude == False:
          createIndexFile(boolNewIndex, indexPath,  scanDirs + '/' + i, baseDirectory)
          boolNewIndex = False
          #print("indexing file: " +  scanDirs + '/' + i)
    else:
        continue
logToFile(strCurrentDirectory + "/duplicate.log","Completed " + str(datetime.datetime.now()) + "\n", False, "a")        
        

