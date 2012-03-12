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
    It sends few ICMP packets with type equal 13 (Timestamp Message) and analyze responses
    http://tools.ietf.org/html/rfc792
    @param nicmp_echoes: Number of ICMP Timestamp requests
'''
def checkICMPTimestamp(host, timeout, nicmp_packets, verbose, progOptions):
    timestamps = []
    timestamp_old = 1
    found = 0
    try:
        utils.printMessage("[*] Analyzing ICMP timestamps...", "info", progOptions)
        # Use Scapy to make some ICMP Timestamp Request (Your ISP could block that or ICMP Timestamp Response)
        answers,unanswered=sr(IP(dst=host)/ICMP(type=13)*nicmp_packets, timeout=timeout)
        if len(answers) > 0:
            for sent, received in answers:
                timestamp = received.getlayer('ICMP').ts_rx
                # If timestamp is greater than last then it's from another host
                if timestamp < timestamp_old:
                    found = 1
                timestamp_old = timestamp
                timestamps.append(timestamp)
            if not found:
                utils.printMessage("   [-] No ICMP inconsistencies found", "less", progOptions)
            else:
                utils.printMessage("   [+] ICMP timestamp inconsistency found", "plus", progOptions)
                if verbose:
                    utils.printMessage("   [v] IPIDs received: %s" %str(timestamps), "verbose", progOptions)
        else:
            utils.printMessage("   [-] No ICMP timestamp request responses", "less", progOptions)
    except KeyboardInterrupt:
        utils.printMessage("[!] Aborted by user...", "error", progOptions)
        sys.exit()
    except Exception, e:
        print str(e)
        sys.exit()   