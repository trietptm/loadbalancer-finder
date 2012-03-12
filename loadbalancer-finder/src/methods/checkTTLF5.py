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


import sys
try:
    from scapy.all import *
except:
    print "[-] You need Scapy (http://www.scapy.org/)"
    sys.exit(0)
conf.verb = 0
import utils

'''
    TTL greater than 230 (and some lower values) commonly seen with F5 Load Balancers
    Also seen in some SOHO Huawei routers....
    Tested on some thousand IP to be almost sure about that
    UDATE: Seen also in some others load balancers, need testing and study
'''
def checkTTLF5(host, port, domain, timeout, progOptions):
    try:
        utils.printMessage("[*] Analyzing IP TTL value", "info", progOptions)
        packet = sr1(IP(dst=domain)/TCP(sport=RandNum(1024,65535), dport=port), timeout=timeout)
        if packet.getlayer('IP').ttl >= 230:
            #utils.printMessage("   [+] IP TTL is %s, so high number is common in F5 Load Balancers" %packet.getlayer('IP').ttl, "plus", progOptions)
            # UPDATE
            utils.printMessage("   [+] IP TTL is %s, so high number is common in some Load Balancers" %packet.getlayer('IP').ttl, "plus", progOptions)
        else:
            utils.printMessage("   [-] No high IP TTL received", "less", progOptions)
    except KeyboardInterrupt:
        utils.printMessage("[!] Aborted by user...", "error", progOptions)
        sys.exit()
    except Exception, e:
        print str(e)
        sys.exit()