sideload
------------
Employs the new sideload feature of Xcode 7 to create 'free' provisioning profiles.

Requires the following depedencies:
 - coda_network
 - BeautifulSoup
 - mechanize
 - plistlib
 - argparse
 - cookielib
 
All of which can be installed via pip.

Usage
------------
```
usage: sideload.py [-h] username password udid appid

Create free provisioning for sideloading on iOS devices.

positional arguments:
 - username    Apple ID (developer) email
 - password    Apple ID (developer) password
 - udid        iOS device UDID
 - appid       A unique bundle identifier

optional arguments
  -h, --help  show this help message and exit
```
