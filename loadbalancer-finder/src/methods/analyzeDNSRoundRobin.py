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
    Use multiple DNS servers around the world to those domain which use Anycast/Round-Robin DNS
    @param nqueries: Number of queries per DNS server used
    @param dns_servers: List of DNS server to query  
'''
def analyzeDNSRoundRobin(domain, nqueries, dns_servers, progOptions):
    try:
        utils.printMessage("[*] Looking for round-robin/anycast DNS", "info", progOptions)
        ips_round = []
        # Make x DNS queries to y DNS Servers
        for x in range(0, nqueries):
            for nameserver in dns_servers:
                res = dns.resolver.Resolver()
                res.nameservers = [nameserver]
                answers = res.query(domain, 'A')
                if len(answers) == 1:
                    ips_round.append(str(answers[0]))
        ips_round = set(ips_round)
        if len(ips_round) > 1:
            utils.printMessage("   [+] DNS round-robin/anycast detected", "plus", progOptions)
            for ip in ips_round:
                utils.printMessage("   <-> Found DNS A entry: %s" % ip, "plus", progOptions)
        else:
            utils.printMessage("   [-] No round-robin/anycast DNS detected", "less", progOptions)
    except KeyboardInterrupt:
        utils.printMessage("[!] Aborted by user...", "error", progOptions)
        sys.exit()
    except Exception, e:
        print str(e)
        sys.exit()