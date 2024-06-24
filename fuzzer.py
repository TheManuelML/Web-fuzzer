## Libraries
import argparse
import signal
import sys
import requests
from pwn import log
from time import strftime
from termcolor import colored


## Version
__version__ = '1.1'


## Arguments / Flags / Parameters
parser = argparse.ArgumentParser(description="Tool to look up for endpoints or directories of certain url")
parser.add_argument("-b", "--blacklist", nargs='+', default=['404'], help="add a list of status codes you want to except separated by a [SPACE], default = 404")
parser.add_argument("-u", "--url", action="store", help="add the URL")
parser.add_argument("-v", "--verbose", action="store_true", help="show also black-listed status codes in the output")
parser.add_argument("-w", "--wordlist", action="store",help="add the path to the wordlist file")

argument = parser.parse_args()


## Saving user data
url = argument.url
wordlist = argument.wordlist

## Creating the blacklist of status codes
if argument.blacklist:
    blacklist = set(argument.blacklist)

## Variable to count successful codes
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
    print("=================  ENUMERATING  ======================")
    print(f"Date: {strftime('%d/%m/%Y')}")
    print(f"Time: {strftime('%H:%M')}")

    print("\nDomain: " + colored(f"{url}", "cyan"))
    ## Printing a more understandable blacklist
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

            ## Saving endpoint in a variable
            endpoint = line.strip()
            ## Executing request and saving the response
            response = requests.head(f"{url}/{endpoint}")
            ## Getting the status code
            status_code = str(response.status_code)

            ## Calling the function to print the results
            report(endpoint, status_code)


## Function to assing colors to the outputs of the status codes
def status_codes_colors(blacklisted, status, url, endpoint):
    ## Assign color depend of the status code
    if status[0] == '1':
        color = "blue"
    elif status[0] == '2':
        color = "green"
    elif status[0] == '3':
        color = "cyan"
    elif status[0] == '4':
        color = "red"
    elif status[0] == '5':
        color = "orange"

    ## Printing the status code of the url with the endpoint
    if blacklisted:
        print(colored("[!] ", "red") + f"{url}/{endpoint} Status: " + colored(f"{status}", color))
    else:
        print(colored("[*] ", "green") + f"{url}/{endpoint} Status: " + colored(f"{status}", color))


## Function to print the enumeration results
def report(endpoint, status):
    ## Declaring some global variables
    global success

    ## Checking status code and assigning colors to each one
    if status not in blacklist:
        ## Call function to assign colors
        status_codes_colors(False, status, url, endpoint)
        ## Add successful code to the count
        success += 1
    else:
        ## If verbose is active, show blacklist status codes
        if argument.verbose:
            ## Call function to assign colors
            status_codes_colors(True, status, url, endpoint)
    return success
    

## Main logic
if __name__ == "__main__":
    if argument.url and argument.wordlist:
        init()
        print("\n=====================  END  ==========================")
        ## Print amount of successful codes
        print("Successful status codes: " + colored(f"{success}", "green"))
    else:
        print("Try adding --help to look for the usage")
        print("At least add --url and --wordlist")
