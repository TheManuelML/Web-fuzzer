## Libraries
import subprocess
import argparse
import signal
import sys
from time import strftime
from pwn import log, context
from termcolor import colored


## Version
__version__ = "1.0"


## Arguments / Flags / Parameters
parser = argparse.ArgumentParser(description="Tool to look up for endpoints or directories of certain url")
parser.add_argument("-b", "--blacklist", nargs='+', default=['404'], help="add a list of status codes you want to except separated by a [SPACE], default = 404")
parser.add_argument("-u", "--url", action="store", help="add the URL")
parser.add_argument("-v", "--verbose", action="store_true", help="show also black-listed status codes in the output")
parser.add_argument("-w", "--wordlist", action="store",help="add the path to the wordlist file")

argument = parser.parse_args()


## Configure pwn context
context.log_level = "info"

## Saving user data
url = argument.url
wordlist = argument.wordlist

## Creating the blcklist of status codes
if argument.blacklist:
    blacklist = set(argument.blacklist)

## Variable to count succesful codes
success = 0


## Function to control "command interrupt ^C" output message
def exit_handler(sig, frame):
    print(colored("\n\n[!] ", "red") + "Interrupted process, " + colored("exiting...", "red"))
    sys.exit(1)
## Ctrl+C
signal.signal(signal.SIGINT, exit_handler)


## Showing fuzzing configuration
def init():
    ## Declaring some global variables
    global success
    global prog

    ## Printing info about the enumeration
    print("===================ENUMERATING========================")
    print(f"Date: {strftime('%d/%m/%Y')}")
    print(f"Time: {strftime('%H:%M')}")

    print("\nDomain: " + colored(f"{url}", "cyan"))
    ## Printing a more undertandable blacklist
    printable_blacklist = ""
    for status_code in blacklist:
        printable_blacklist += f"{status_code} "
    print(f"Blacklist: " + colored(f"[ {printable_blacklist}]", "red"))
    print("======================================================")
    
    ## Creating variable for progress
    prog = log.progress("Enumeration") 
    prog.status("Starting [0]")
    print("")

    ## Calling the function to start the enumeration
    directory_enumeration()


## Opening wordlist file
def directory_enumeration():
    ## Declaring some global variables
    global success

    ## Counting number of lines read from the dictionary
    i = 0
    with open(wordlist, 'r') as file:
        ## Reading line per line
        for line in file:
            ## Updating progress bar
            i += 1 
            prog.status(colored(f"Words tried [{i}] ", "blue"))

            ## Saving directorie in a variable
            endpoint = line.strip()
            ## Executing command and saving the output
            command = subprocess.run(["curl", "-I" , f"{url}/{endpoint}"], capture_output=True, text=True)
            ## Getting the status code
            output = command.stdout.split('\n')
            status_code = output[0].split(' ')[1] if output else '0'

            ## Calling the function to print the results
            report(endpoint, status_code)


## Function to print the enumeration results
def report(endpoint, status):
    ## Declaring some global variables
    global success

    ## Checking status code
    if status not in blacklist:
        print(colored(f"[*] ", "green") + f"{url}/{endpoint} Status: " + colored(f"{status}", "green"))
        ## Add succesful code to the count
        success += 1
    else:
        ## If verbose is active, show blacklist status codes
        if argument.verbose:
            print(colored(f"[!] ", "red") + f"{url}/{endpoint} Status: " + colored(f"{status}", "red"))
    return success
    

## Main logic
if __name__ == "__main__":
    if argument.url and argument.wordlist:
        init()
        print("=======================END============================")
        ## Print amount of successful codes
        print("Successful codes: " + colored(f"{success}", "green"))
    else:
        print("Try adding --help to look for the usage")
        print("At least add --url and --wordlist")