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

'''
    It makes few HTTP GET requests and look for different "Server" headers in them.
    @param nrequest: Number of request to extract HTTP 'server' header
'''
def analyzeServerBannerDiff(host, port, ssl, nrequests, useragent, timeout, progOptions):
    servers = []
    try:
        utils.printMessage("[*] Looking for banner inconsistencies", "info", progOptions)
        # Make x requests to get "server" header
        for x in range(0,nrequests):
            header = utils.getHTTPHeader(host, port, ssl, "server", useragent, timeout, progOptions)
            if header:
                servers.append(header.rstrip())
        # A set is an unordered collection with no duplicate elements.
        # Basic uses include membership testing and eliminating duplicate entries (Python DOC)
        if len(set(servers)) > 1:
            utils.printMessage("   [+] Multiple HTTP server banners found", "plus", progOptions)
            for server in servers:
                utils.printMessage("      <-> %s" %server, "plus", progOptions)
        else:
            utils.printMessage("   [-] No banner inconsistencies found", "less", progOptions)
    except KeyboardInterrupt:
        utils.printMessage("[!] Aborted by user...", "error", progOptions)
        sys.exit()
    except Exception, e:
        print str(e)
        sys.exit()   