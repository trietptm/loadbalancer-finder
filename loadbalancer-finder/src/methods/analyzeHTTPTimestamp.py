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
import time
import sys
import re
from datetime import datetime

'''
    It makes few HTTP GET requests and analyze timestamp if present
    http://tools.ietf.org/html/rfc2616
    @param nrequest: Number of request to extract HTTP 'date' header
'''        
def analyzeHTTPTimestamp(host, port, ssl, nrequests, useragent, timeout, verbose, progOptions):
    try:
        utils.printMessage("[*] Looking for HTTP timestamps inconsistencies", "info", progOptions)
        timestamps = []
        found = 0

        utc_old = datetime.strptime('Thu, 03 Nov 1666 01:36:28', '%a, %d %b %Y %H:%M:%S')
        # Make x requests to detect inconsistencies
        for x in range(0,int(nrequests)):
            # Get only 'date' header
            header = utils.getHTTPHeader(host, port, ssl, "date", useragent, timeout, progOptions)
            if header:
                timestamp = re.search("(.+ \d{0,2}:\d{0,2}:\d{0,2})", header).group(1)
                # Convert date header to struct_time
                utc = datetime.strptime(timestamp, '%a, %d %b %Y %H:%M:%S')
                # If timestamp is greater than last then it's from another host
                if utc < utc_old:
                    found = 1
                utc_old = utc
                timestamps.append(utc)
        if len(timestamps) == 0:
            utils.printMessage("   [-] No HTTP timestamps received", "less", progOptions)
            return
        if not found:
            utils.printMessage("   [-] No HTTP timestamps inconsitencies found", "less", progOptions)
        else:
            utils.printMessage("   [+] Timestamp inconsistency found", "plus", progOptions)
            # Convert datetime to UNIX timestamp
            for index, timestamp in enumerate(timestamps):
                timestamps[index] = int(time.mktime(timestamp.timetuple()))
            if verbose:
                utils.printMessage("   [v] Timestamps received: %s" %str(timestamps), "verbose", progOptions)
    except KeyboardInterrupt:
        utils.printMessage("[!] Aborted by user...", "error", progOptions)
        sys.exit()
    except Exception, e:
        print str(e)
        sys.exit()    