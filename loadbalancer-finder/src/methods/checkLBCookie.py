'''
Load Balancer Finder - Try to detect load balancers / domain using multiple hosts
Copyright (C) 2011  Alejandro Nolla Blanco - alejandro.nolla@gmail.com 
Nick: z0mbiehunt3r - @z0mbiehunt3r
Blog: navegandoentrecolisiones.blogspot.com

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
'''


import re
import sys
from bigip_cookie_decoder import *
import utils

'''
    It makes one HTTP GET request and look for a series of well-known load balancer cookies
    @param f5enumeration: Number of HTTP requests to get cookies and enumerate internal IP:port pair
'''
def checkLBCookie(host, port, ssl, useragent, timeout, f5enumeration, progOptions):
    f5 = 0
    lbdetected = ""
    try:
        utils.printMessage("[*] Looking for known load balancers cookies", "info", progOptions)
        cookie = utils.getHTTPHeader(host, port, ssl, "set-cookie", useragent, timeout, progOptions)
        if cookie:
            # Lookup for some known cookies - Send me yours!
            if re.search("BIGipServer", cookie) or re.search('\d{8,10}\.\d{1,5}\.\d{4}', cookie):
                lbdetected = "   [+] F5 load balancer detected"
                f5 = 1
            elif re.search("KEMPID=", cookie):
                lbdetected = "   [+] KEMP Technologies load balancer detected"
            elif re.search("ROUTEID:", cookie) or re.search("sticky-session=", cookie) or re.search("BALANCEID", cookie):
                lbdetected = "   [+] mod_proxy_balancer load balancer detected"
            elif re.search("SERVERID=", cookie):
                lbdetected = "   [+] HAProxy load balancer detected"
            elif re.search("ACE-Insert=", cookie):
                lbdetected = "   [+] Cisco ACE load balancer detected"
            elif re.search("jnAccel", cookie):
                lbdetected = "   [+] jetNexus load balancer detected"    
            elif re.search("BARRACUDA_LB_COOKIE", cookie):
                lbdetected = "   [+] Barracuda load balancer detected"                
            elif re.search("NSC_", cookie):
                lbdetected = "   [+] Net Scaler load balancer detected"                
            elif re.search("X-RBT-Optimized", cookie):
                lbdetected = "   [+] Riverbed load balancer detected"                
            elif re.search("FGTServer", cookie):
                lbdetected = "   [+] Fortigate load balancer detected"                
            elif re.search("Coyote-", cookie):
                lbdetected = "   [+] CoyotePoint load balancer detected"                
                
            if lbdetected != "":
                utils.printMessage(lbdetected, "plus", progOptions)
                if f5:
                    utils.printMessage("   [*] Going to enumerate some internal IPs", "info", progOptions)
                    try:
                        for x in range(0, int(f5enumeration)):
                            cookie = utils.getHTTPHeader(host, port, ssl, "set-cookie", useragent, timeout, progOptions)
                            BIGIPCookieDecoder(cookie, progOptions)
                    except NameError, e:
                        utils.printMessage("      [-] Encoded cookie didn't have encoded info", "less", progOptions)
        if lbdetected == "":
            utils.printMessage("   [-] No known load balancer cookie detected", "less", progOptions)
    except KeyboardInterrupt:
        utils.printMessage("[!] Aborted by user...", "error", progOptions)
        sys.exit()
    except Exception, e:
        print str(e)
        sys.exit()