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


def analyzeServerBanner(host, port, ssl, useragent, timeout, progOptions):
    """It makes few HTTP Get requests and look for known Server headers used in load balancers
    :param host: Host a analizar
    """
    
    lb_detected = ""
    
    try:
        # Make x requests to get "server" header
        server_header = utils.getHTTPHeader(host, port, ssl, "server", useragent, timeout, progOptions)
        # A set is an unordered collection with no duplicate elements.
        # Basic uses include membership testing and eliminating duplicate entries (Python DOC)
        if server_header == "Cisco Acceleration":
            lb_detected = "Cisco ACE Accelerator"
        elif server_header == "BigIP":
            lb_detected = "F5 BigIP"
    except Exception, e:
        raise e
    
    return lb_detected
