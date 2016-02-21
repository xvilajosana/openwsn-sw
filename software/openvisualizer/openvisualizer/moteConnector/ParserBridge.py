# Copyright (c) 2010-2013, Regents of the University of California. 
# All rights reserved. 
#  
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License
import logging
log = logging.getLogger('ParserBridge')
log.setLevel(logging.ERROR)
log.addHandler(logging.NullHandler())

import struct

from pydispatch import dispatcher

from ParserException import ParserException
import Parser

class ParserBridge(Parser.Parser):
    
    HEADER_LENGTH  = 2

    FAIL     = ord('F')
    SENDDONE = ord('S')
    FROMMESH = ord('F')
    TOMESH   = ord('T')
    NEIGHBOR = ord('N')
     
    def __init__(self):
        
        # log
        log.info("create instance")
        
        # initialize parent class
        Parser.Parser.__init__(self,self.HEADER_LENGTH)
    
    #======================== public ==========================================
    
    def parseInput(self,input):
        # log
        if log.isEnabledFor(logging.DEBUG):
            log.debug("received packet {0}".format(input))
        
        # ensure input not short longer than header
        self._checkLength(input)
   
        headerBytes = input[:2]
        
        # remove mote id at the beginning.
        input = input[2:]
        
        if log.isEnabledFor(logging.DEBUG):
            log.debug("bridge without header {0}".format(input))
       
	eventType = 'fragabort' if input[0] == self.FAIL else 'fragsent'

	if input[1] == self.TOMESH:
            incoming = 1
	elif input[1] == self.NEIGHBOR:
            incoming = 2
        else:
	    incoming = 7
	tag = ''
	input = input[2:]
	if incoming & 1:
            tag += str((input[0] << 8) + input[1])   #tag
	    input = input[2:]
	if incoming & 4:
            tag += str(input[0] & 7) + str(input[1]) # size
	    input = input[2:]
	if incoming & 2:
	    tag += str(input[0:])                    # source or destination
        return (eventType,(incoming,tag))

 #======================== private =========================================
