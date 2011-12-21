#!/usr/bin/env python

# Description:
#          Python script to decode F5 BIG-IP persistent cookies
#
# Author:  Raul Siles (raul _AT_ taddong _DOT_ com)
#          Taddong (www.taddong.com)
# Date:    2011-12-06
# Version: 0.1

# URL: http://www.taddong.com/tools/BIG-IP_cookie_decoder.py
# F5:  http://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html
# Fix: http://support.f5.com/kb/en-us/solutions/public/7000/700/sol7784.html

# Credits: (based on) 
# http://penturalabs.wordpress.com/2011/03/29/how-to-decode-big-ip-f5-persistence-cookie-values/

# Example cookie value (encoded string): 1677787402.36895.0000


import struct
import re
import utils

def BIGIPCookieDecoder(cookie, progOptions):
    encoded_string = re.search("\d{10}\.\d{5}\.\d{4}", cookie)
    if encoded_string is not None:
        encoded_string = encoded_string.group(0) 
        (host, port, end) = encoded_string.split('.')
        # Hexadecimal details:
        (a, b, c, d) = [ord(i) for i in struct.pack("<I", int(host))]
        #print "HOST: 0x%02X 0x%02X 0x%02X 0x%02X\n" % (a,b,c,d)
        (v) = [ord(j) for j in struct.pack("<H", int(port))]
        p = "0x%02X%02X" % (v[0],v[1])
        utils.printMessage("      <-> Decoded cookie: %s.%s.%s.%s:%s" % (a,b,c,d, int(p,16)), "plus", progOptions)
    else:
        raise NameError('F5-nodata')
