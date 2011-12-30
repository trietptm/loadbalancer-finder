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
try:
    from pyx import *
except:
    print "[-] You need PYX (http://pyx.sourceforge.net/)"
    sys.exit(0)    
import utils

'''
    It sends few TCP packets with SYN flag on and analyze ID value of IP response's header.
    If they are not always zero or not incrementally increasing we can deduce there are several servers answering
    
    "The originating protocol module of
    an internet datagram sets the identification field to a value that
    must be unique for that source-destination pair and protocol for the
    time the datagram will be active in the internet system."
    
    "It seems then that a sending protocol module needs to keep a table
    of Identifiers, one entry for each destination it has communicated
    with in the last maximum packet lifetime for the internet."
    
    "However, since the Identifier field allows 65,536 different values,
    some host may be able to simply use unique identifiers independent
    of destination."
    
    http://tools.ietf.org/html/rfc791
    @param nsyn: Number of TCP packets with SYN flag activated to send
'''
def analyzeIPID(domain, port, nsyn, timeout, verbose, progOptions):
    conf.verb = 0
    ipids = []
    found = 0
    try:
        utils.printMessage("[*] Analyzing IPID sequence...", "info", progOptions)
        # Use Scapy to make some TCP SYN requests
        answers,unanswered=sr(IP(dst=domain)/TCP(sport=RandNum(1024,65535), dport=port)*nsyn, timeout=timeout)

        for sent, received in answers:
            ipids.append(received.getlayer('IP').id)
        
        # Loop from first IPID through penultimate
        for x, ipid in enumerate(ipids[0:-1]):
            # And compare it from current position+1 until last IPID
            for ipid2 in ipids[x+1:]:
                if ipid > ipid2:
                    found = 1
        if found:
            utils.printMessage("   [+] IPID inconsistency found", "plus", progOptions)
        if len(set(ipids)) == 1:
            utils.printMessage("   [-] IPID always zero", "less", progOptions)
        else:
            utils.printMessage("   [+] IPID incremental", "plus", progOptions)
            utils.printMessage("   [+] It's seem to be %i servers" % getNumHostsfromIPIDS(ipids), "plus", progOptions)
            # Plot IPID in some axis (maybe useful for some reports)
            g = pyx.graph.graphxy(width=15,height=10)
            g.plot(pyx.graph.data.points(zip(range(0,nsyn), ipids), x=1, y=2))
            fname = domain+"_ipids.jpg"
            g.pipeGS(filename=fname,device="jpeg")
            utils.printMessage("   [+] Generated %s file with plotted IPIDS" % fname, "info", progOptions)
            if verbose:
                utils.printMessage("   [v] IPIDs received: %s" %str(ipids), "verbose", progOptions)
    except KeyboardInterrupt:
        utils.printMessage("[!] Aborted by user...", "error", progOptions)
        sys.exit()
    except Exception, e:
        print str(e)
        sys.exit()
        
'''
This function calculate the number of hosts behind load balancer identifying great distances between different values of IPIDS sequences.

Credits:
Ruben Garrote Garcia - rubengarrote@gmail.com
Nick: Boken - boken00@gmail.com
Blog: boken00.blogspot.com
    
    @return: Number of detected  hosts (aprox)
'''
def getNumHostsfromIPIDS(ipids):    
    """ Get the number of hosts behind load balancers that there are behind the host """
    def getDistances(ipids):
        """ Local function to calculate the distances between each element in a list. Return a sorted list with distances. """
        ipids.sort()
        # Initialize the distances list and first value to IPID
        distances = []
        lastIPID = 0
        for ipid in ipids:
            # Get distances between two elements and store the current element as the last element.
            distances.append(ipid-lastIPID)
            lastIPID = ipid
        # Sort the values gotten and return this.
        distances.sort()
        return distances
    
    # Iterate many times to clear the noise and get only significant distances to calculate the number of load balancers.
    for i in range(0,8):
        ipids = getDistances(ipids)
    # Remove zero values.
    distances = [x for x in ipids if x > 0]
    
    return int(len(distances)-1)
