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
import httplib
import re

class cParams():
    '''
    Class used to set some parameters
    '''
    def __init__(self):
        '''
        Constructor
        '''
        self.USE_COLOURS = False
        self.NORMAL_OUTPUT = None # writer for output, normaly the screen
        self.ERROR_OUTPUT = None # writer for outpu, normaly the screen
        self.args = []

    def get_use_colours(self):
        return self.USE_COLOURS


    def get_normal_output(self):
        return self.NORMAL_OUTPUT


    def get_error_output(self):
        return self.ERROR_OUTPUT


    def set_use_colours(self, value):
        self.USE_COLOURS = value


    def set_normal_output(self, value):
        self.NORMAL_OUTPUT = value


    def set_error_output(self, value):
        self.ERROR_OUTPUT = value


    def del_use_colours(self):
        del self.USE_COLOURS


    def del_normal_output(self):
        del self.NORMAL_OUTPUT


    def del_error_output(self):
        del self.ERROR_OUTPUT

    USE_COLOURS = property(get_use_colours, set_use_colours, del_use_colours, "USE_COLOURS's docstring")
    NORMAL_OUTPUT = property(get_normal_output, set_normal_output, del_normal_output, "NORMAL_OUTPUT's docstring")
    ERROR_OUTPUT = property(get_error_output, set_error_output, del_error_output, "ERROR_OUTPUT's docstring")

'''
    Function used to print some message to file descriptor
    @param message: Message to show, format like "[+] Message" or "<-> Message"
    @param type: Type of error - info/less/plus/error/verbose
'''
def printMessage(message, type, options):
    # Split "prompt" from message like "[!] Some weird error" or like "<-> Some info"
    srematch = re.search("(\s*[\[\<].{1}[\]|>])(.+)", message)
    message_original = message
    prompt = srematch.group(1)
    message = srematch.group(2)
    if type == "info":
        if options.USE_COLOURS: 
            options.NORMAL_OUTPUT.write(chr(27)+"[0;93m"+prompt+chr(27)+"[0m")
            options.NORMAL_OUTPUT.write(message+"\n")
        else:
            options.NORMAL_OUTPUT.write(message_original+"\n")
    elif type == "less":
        if options.USE_COLOURS:
            options.NORMAL_OUTPUT.write(chr(27)+"[0;34m"+prompt+chr(27)+"[0m")
            options.NORMAL_OUTPUT.write(message+"\n")
        else:
            options.NORMAL_OUTPUT.write(message_original+"\n")
    elif type == "plus":
        if options.USE_COLOURS:
            options.NORMAL_OUTPUT.write(chr(27)+"[0;32m"+prompt+chr(27)+"[0m")
            options.NORMAL_OUTPUT.write(message+"\n")
        else:
            options.NORMAL_OUTPUT.write(message_original+"\n")
    elif type == "error":
        if options.USE_COLOURS:
            options.ERROR_OUTPUT.write(chr(27)+"[0;31m"+prompt+chr(27)+"[0m")
            options.ERROR_OUTPUT.write(message+"\n")
        else:
            options.NORMAL_OUTPUT.write(message_original+"\n")
    elif type == "verbose":
        if options.USE_COLOURS:
            options.NORMAL_OUTPUT.write(chr(27)+"[0;35m"+prompt+chr(27)+"[0m")
            options.NORMAL_OUTPUT.write(message+"\n")
        else:
            options.NORMAL_OUTPUT.write(message+"\n")

'''
    Function used to get just one HTTP header
'''
def getHTTPHeader(host, port, ssl, header, useragent, http_timeout, progOptions):
    try:
        headers = {'User-agent': useragent,
                   'Host': host,
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                   'Accept-Encoding': 'gzip,deflate',
                   'Proxy-Connection': 'keep-alive'
                   }
        if not ssl:
            conn = httplib.HTTPConnection(host, port, timeout=http_timeout)
            conn.request("GET", "http://%s/" %host , headers=headers)
        else:
            conn = httplib.HTTPSConnection(host, port, timeout=http_timeout)
            conn.request("GET", "https://%s/" % host, headers=headers)
        response = conn.getresponse()
        return response.getheader(header)
    except KeyboardInterrupt:
        printMessage("[!] Aborted by user...", "error", progOptions)
        sys.exit()
    except Exception, e:
        print str(e)
        sys.exit()

'''
    Function used to read DNS servers from a file
'''
def readDNSServers(dnsserversfile, progOptions):
    ''' 
        Google - 8.8.8.8 
        Advantage - 156.154.70.1
        Telefonica - 80.58.61.250
        OpenDNS - 208.67.222.222 
        DNS Advantage - 156.154.70.1
        http://www.tech-faq.com/public-dns-servers.html
    '''
    try:
        fd = open(dnsserversfile, "r")
        dnsservers = fd.readlines()
        fd.close()
        return map(str.rstrip,dnsservers)
    except IOError:
        printMessage("[!] Error al abrir el fichero", "error", progOptions)
        sys.exit(0)