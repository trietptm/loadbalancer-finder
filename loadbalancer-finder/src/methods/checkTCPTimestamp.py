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
    It sends few TCP packets with flag SYN on and using progOptions extension indicating timestamp
    trying to get responses with timestamp to check them
    http://tools.ietf.org/html/rfc1323
    @param ntcp_timestamp: Number of TCP packets with timestamp option activated to send
'''    
def checkTCPTimestamp(host, port, ntcp_timestamp, timeout, verbose, progOptions):
    timestamps = []
    timestamp_old = 1
    found = 0
    try:
        utils.printMessage("[*] Analyzing TCP timestamps...", "info", progOptions)
        # Set "Timestamp" option to avoid some firewall dropping packet 
        answers,unanswered=sr(IP(dst=host)/TCP(sport=RandNum(1024,65535), dport=port, options=[('Timestamp',(0,0))])*ntcp_timestamp, timeout=timeout)
        for sent, received in answers:
            options = received.getlayer('TCP').options
            for option in options:
                if option[0] == 'Timestamp':
                    timestamp = option[1][0]
                    # If timestamp is greater than last then it's from another host
                    if timestamp < timestamp_old and timestamp !=0:
                        found = 1
                    timestamp_old = timestamp
                    timestamps.append(timestamp)
        if len(timestamps) == 0:
            utils.printMessage("   [-] No TCP timestamps received", "less", progOptions)
            return
        if not found:
            utils.printMessage("   [-] No TCP timestamps inconsistencies found", "less", progOptions)
        else:
            utils.printMessage("   [+] TCP timestamp inconsistency found", "plus", progOptions)
            if verbose:
                utils.printMessage("   [v] TCP timestamps received: %s" %str(timestamps), "verbose", progOptions)
    except KeyboardInterrupt:
        utils.printMessage("[!] Aborted by user...", "error", progOptions)
        sys.exit()
    except Exception, e:
        print str(e)
        sys.exit()    
