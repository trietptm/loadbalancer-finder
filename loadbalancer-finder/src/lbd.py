#!/usr/bin/python
# -*- coding: utf-8 -*-

'''
Load Balancer Finder - Try to detect load balancers / domain using multiple hosts
Copyright (C) 2011  Alejandro Nolla Blanco - alejandro.nolla@gmail.com 
Nick: z0mbiehunt3r - @z0mbiehunt3r
Blog: navegandoentrecolisiones.blogspot.com


Thanks to:
Rubén Garrote García (Boken) for ideas, helping me and his getNumLBfromIPIDS function
Daniel García García (Crohn) for ideas and helping me
Raúl Siles for his F5 BIGIP Cookie Decoder script

Buguroo and Ecija team!


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


'''
So understand
Don't waste your time always searching for those wasted years,
Face up...make your stand,
And realize you're living in the golden years.
    Iron Maiden - Wasted Years
'''


import sys
import ConfigParser
import argparse
import utils
import methods
import updater
import os



def banner():
    banner = '''
        |----------------------------------------------------------|
        |                    Load Balancer Finder                  |
        |               Alejandro Nolla (z0mbiehunt3r)             |
        |----------------------------------------------------------|\n'''
    print banner

def usage():
    print '''
Tries to find load balancers using several methods:
    - Check multiple DNS "A" entries
    - IPID Analysis
    - IP TTL value analysis
    - Server banner analysis
    - Well-known load balancer cookies checking
    - HTTP Date header timestamp analysis
    - ICMP timestamp analysis
    - TCP timestamp analysis
    - Multiple DNS queries with different geolocated DNS servers (round-robin, anycast)
    '''

def checkArgs():
    if len(sys.argv) < 2:
        usage()
        parser.print_help()
        sys.exit()


if __name__ == '__main__':
    
    banner()
    
    
    parser = argparse.ArgumentParser()
    gr1 = parser.add_argument_group("Main options")
    gr1.add_argument('-d', '--domain', dest='domain', required=False, help='domain to check')
    gr1.add_argument('-p', '--port', dest='port', required=False, default=80, type=int, help='port to check (default 80)')
    gr1.add_argument('-s', '--ssl', dest='ssl', default=False,  action='store_true', help='use SSL to HTTP request')
    gr1.add_argument('-f', '--file', dest='configfile', default="lb-finder.conf",  help='config file to use')
    
    gr2 = parser.add_argument_group("Disply options")
    gr2.add_argument('-v', '--verbose', dest='verbose', default=False,  action='store_true', help='show extra info about IPIDs, timpestamps, etc')
    gr2.add_argument('-c', '--colours', dest='colour', default=False,  action='store_true', help='coloured output')
    
    gr3 = parser.add_argument_group("Update options")
    gr3.add_argument('-u','--update', dest='update', action='store_true', help='update Load Balancer Finder')
    
    checkArgs()
    
    args = parser.parse_args()
          
    progOptions = utils.cParams()
    progOptions.set_normal_output(sys.stdout)
    progOptions.set_error_output(sys.stderr)
    progOptions.set_use_colours(args.colour)
    progOptions.verbose = args.verbose
    
    
    if args.update:
        utils.printMessage("[*] Going to update Load Balancer Finder", "info", progOptions)
        updater.update()
        sys.exit(1)
    
    
    if not os.geteuid()==0:
        utils.printMessage("[-] You have to be root (scapy packet injection)", "error", progOptions)
        sys.exit(0)
    
    
    # Configuration parsing
    cfg = ConfigParser.ConfigParser()
    try:
        cfg.read(args.configfile)
        nsyn = int(cfg.get("packets","ipid_syn"))
        nicmp_packets = int(cfg.get("packets","nicmp_packets"))
        tcp_timestamp = int(cfg.get("packets","tcp_timestamp"))
        banner_retrieves = int(cfg.get("packets","banner_retrieves"))
        cookie_retrieves = int(cfg.get("packets","cookie_retrieves"))
        httptimestamp_retrieves = int(cfg.get("packets","httptimestamp_retrieves"))
        socket_timeout = int(cfg.get("packets","socket_timeout"))
        http_timeout = int(cfg.get("HTTP","http_timeout"))
        dns_queries = int(cfg.get("packets","dns_queries"))
        useragent = cfg.get("HTTP","useragent")
        f5enumeration = cfg.get("HTTP", "f5enumeration")
    except:
        utils.printMessage("[-] Error parsing config options (check lb-finder.conf for reference)", "error", progOptions)
        sys.exit(0) 

    
    # Battery tests
    dns_servers_round_robin = utils.readDNSServers("dnsservers.txt", progOptions)
    
    domain = args.domain
    host = domain
    port = args.port
    domain = domain.rstrip()
    verbose = args.verbose
    utils.printMessage("[*] Looking for load balancers in %s\n" %domain, "info", progOptions)
    methods.checkMultipleDNS(domain, progOptions)
    methods.analyzeIPID(domain, port, nsyn, socket_timeout, verbose, progOptions)
    methods.checkTTLF5(host, port, domain, socket_timeout, progOptions)
    methods.analyzeServerBannerDiff(host, port, args.ssl, banner_retrieves, useragent, http_timeout, progOptions)
    methods.checkLBCookie(host, port, args.ssl, useragent, http_timeout, f5enumeration, progOptions)
    methods.analyzeHTTPTimestamp(host, port, args.ssl, httptimestamp_retrieves, useragent, http_timeout, verbose, progOptions)
    methods.checkICMPTimestamp(host, socket_timeout, nicmp_packets, args.verbose, progOptions)
    methods.checkTCPTimestamp(host, port, tcp_timestamp, socket_timeout, args.verbose, progOptions)
    methods.analyzeDNSRoundRobin(domain, dns_queries, dns_servers_round_robin, progOptions)
    utils.printMessage("[*] Looking for known load balancers HTTP 'Server' header", "info", progOptions)
    lb = methods.analyzeServerBanner(host, port, args.ssl, useragent, http_timeout, progOptions)
    if lb:
        utils.printMessage("   [+] Known HTTP 'Server' header found for %s" %lb, "plus", progOptions)
    else:
        utils.printMessage("   [-] No known HTTP 'Server' header found", "less", progOptions)
    
    utils.printMessage("[-] All tests done...\n\n", "info", progOptions)
