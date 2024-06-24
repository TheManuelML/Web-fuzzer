# Directory enumeration
Linux script that enumerates directories in a domain using a dictionary. Create a blacklist to exclude specific status codes. Up to 30 searches every 10 seconds.

## Prepare
```
>> git clone https://github.com/TheManuelML/webFuzzer
>> cd webFuzzer

>> python3 -m venv venv
>> source venv/bin/activate

>> pip install -r requirements.txt
```

## Run
```
>> python3 pyBuster.py --help
```

## Options
- -b, --blacklist Write a list of status codes that are going to be excepted. By default is only the status code: 404.
- -u, --url A parameter to add the URL.
- -v, --verbose Show also the searches that return a status code that is in the blacklist.
- -w, --wordlist A parameter to add the wordlist used to make the searches.

## Example
![Example_image](https://github.com/TheManuelML/dirEnumeration/assets/82970354/69ea1b3c-0320-43b4-884c-e355da9df3f9)
