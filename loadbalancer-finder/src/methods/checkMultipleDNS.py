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

import utils
import sys
try:
    import dns.resolver
except:
    print "[-] You need DNS-python (http://www.dnspython.org/)"
    sys.exit(0)



'''
    It makes a DNS lookup and search for multiple A entries in same answers
    http://tools.ietf.org/html/rfc1035
'''
def checkMultipleDNS(domain, progOptions):
    try:
        utils.printMessage("[*] Checking multiple A DNS entries...", "info", progOptions)
        try:
            answers = dns.resolver.query(domain, 'A')
        except dns.exception.DNSException:
            utils.printMessage("[!] DNS lookup failed", "error", progOptions)
            sys.exit()
        if len(answers) > 1:
            utils.printMessage("   [+] Multiple A DNS entries found", "plus", progOptions)
            for rdata in answers:
                utils.printMessage("      <-> %s" %rdata, "plus", progOptions)
        else:
            utils.printMessage("   [-] Just one DNS entry found: %s" %answers[0], "less", progOptions)
    except KeyboardInterrupt:
        utils.printMessage("[!] Aborted by user...", "error", progOptions)
        sys.exit()
    except Exception, e:
        print str(e)
        sys.exit()