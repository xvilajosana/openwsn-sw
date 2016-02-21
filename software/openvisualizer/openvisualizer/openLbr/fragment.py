# Copyright (c) 2010-2015, Regents of the University of California. 
# All rights reserved. 
#  
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License
import logging
log = logging.getLogger('fragment')
log.setLevel(logging.ERROR)
log.addHandler(logging.NullHandler())

from openvisualizer.eventBus import eventBusClient
import random
import threading
import openvisualizer.openvisualizer_utils as u

#============================ parameters ======================================

class Fragment(eventBusClient.eventBusClient):
    '''
    Class which is responsible for 6LoWPAN fragmentation.
    
    This class implements section 5.3 of the following RFC:
    
    * *http://tools.ietf.org/html/rfc4944
      Transmission of IPv6 Packets over IEEE 802.15.4 Networks (fragmentation)
    '''

    FRAGMENT_DISPATCH = 3
    FRAGMENT_FRAG1    = 0x18
    FRAGMENT_FRAGN    = 0x1C

    FRAGMENT_SKIP_BYTES = 4   # Bytes to skip on frame when FRAG1
    FRAGMENT_DATA_UTIL  = 125 # Frame payload

    L2_HSIZE = 8+8+2+1+2 # myIP(8B) + next(8B) + MyID(2B) + DSN + FCF

    LENGTH_IPV6_MTU = 1280
    
    def __init__(self):
        
        # log
        log.info("create instance")
        
        # store params
        self.stateLock            = threading.Lock()
        self.sndfragments         = {} # outgoing messages
        self.rcvfragments         = {} # incoming messages

	self.tag = random.randint(0,0xFFFF)
         
        # initialize parent class
        eventBusClient.eventBusClient.__init__(
            self,
            name             = 'Fragment',
            registrations =  [
                {
                    'sender'   : self.WILDCARD, #fragment a message to be sent to the mesh
                    'signal'   : 'fragment',
                    'callback' : self._fragment_notif,
                },
                {
                    'sender'   : self.WILDCARD,
                    'signal'   : 'fragsent', #signal fragment can be send to the mesh
                    'callback' : self._fragsent_notif,
                },
                {
                    'sender'   : self.WILDCARD,
                    'signal'   : 'fromMote.fragsent', #signal fragment can be send to the mesh
                    'callback' : self._fragsent_notif_mote,
                },
                {
                    'sender'   : self.WILDCARD,
                    'signal'   : 'fromMote.fragabort', #signal an error for a fragmented message
                    'callback' : self._fragabort_notif, 
                },
                {
                    'sender'   : self.WILDCARD, #signal when a pkt from the mesh arrives and has to be forwarded to Internet (or local)
                    'signal'   : 'fromMote.data', #only to data (any), not status nor error
                    'callback' : self._assemble_notif, 
                },
            ]
        )
        
        # local variables
            
    #======================== public ==========================================
    
    #======================== private =========================================
    
    #===== Fragmentation
    
    def _fragment_notif(self,sender,signal,data):
        '''
        Fragments a 6LoWPAN packet, if needed.
        
        This function dispatches the signal 'fragment.sent'.
        '''
        
        try:
            nextHop      = data[0]
            iphc         = data[1]
            payload      = data[2]
            max_fragment = self.FRAGMENT_DATA_UTIL - self.L2_HSIZE
            size         = len(iphc) + len(payload)
            if size <= max_fragment:
                # dispatch
                self.dispatch(
                    signal       = 'bytesToMesh',
                    data         = (nextHop,iphc+payload),
                )
                return

	    if log.isEnabledFor(logging.DEBUG):
                output  = "Sending fragments: "
	        output += "iphc = " + str(len(iphc))
	        output += " - payload = " + str(len(payload))
            max_fragment    -= self.FRAGMENT_SKIP_BYTES
            actual_frag_size = max_fragment & 0xF8
	    if actual_frag_size < len(iphc):
                raise ValueError('unsupported IPHC size')

            tag  = self._getNewTag()
            stag = str(tag) #+str(size)+str(nextHop)
            # Using just tag as it is fixed by me and it is unique
            # frag contains a triplet (data,offset,sent) for every fragment
            self.sndfragments[stag] = {'frag':[], 'size': size, 'tag': tag, 'nextHop': nextHop}

	    input = iphc+payload
	    if len(input) > self.LENGTH_IPV6_MTU:
	        raise ValueError('unsupported packet size')

	    self.sndfragments[stag]['frag'].append({'data': input[0:actual_frag_size], 'offset': 0, 'sent': False})
            actual_sent   = actual_frag_size
            max_fragment -= 1
            actual_frag_size = max_fragment & 0xF8
            while actual_sent < size:
	        if actual_frag_size > size - actual_sent:
                    actual_frag_size = size - actual_sent
		self.sndfragments[stag]['frag'].append({'data': input[actual_sent:actual_sent+actual_frag_size], 'offset': actual_sent, 'sent': False})
                actual_sent += actual_frag_size

	    if log.isEnabledFor(logging.DEBUG):
                output += " - offsets ="
                for i in self.sndfragments[stag]['frag']:
                    output += " " + str(i['offset'])
                log.debug(output)

            print "Sending message of " + str(len(iphc)) + "/" + str(len(input)) + " in " + str(len(self.sndfragments[stag]['frag'])) + " fragments"
            self.dispatch(
                signal = 'fragsent',
                data   = stag,
            )
            #return
            
        except (ValueError) as err:
            log.error(err)
            pass
    
    
    def _assemble_notif(self,sender,signal,data):
        '''
        Assembles 6LowPAN fragmented packets into an entire 6LowPAN packet.
        
        This function dispatches the 6LowPAN packet with signal 'fromMote.data'.
        '''
        pkt        = data[1]
        fragmented = pkt[0] >> self.FRAGMENT_DISPATCH
        if fragmented != self.FRAGMENT_FRAG1 and \
           fragmented != self.FRAGMENT_FRAGN:
            self.dispatch(
               signal = 'meshToV6',
               data   = data,
            )
            return
  
        # Packet is fragmented
        # Create a tag mapping from tag+size+source.
	stag  = str((pkt[2] << 8) + pkt[3])
	stag += str(pkt[0] & 7) + str(pkt[1])
	stag += str(data[0])

	size   = ((pkt[0] & 7) << 8) + pkt[1] 
	tag    = (pkt[2] << 8) + pkt[3]
        offset = 0 if fragmented == self.FRAGMENT_FRAG1 else pkt[4]

        # First time this tag arrives
	if not stag in self.rcvfragments:
#            self.rcvfragments[stag] = {'input':[], 'length':[], 'size': size}
            self.rcvfragments[stag] = {'input':{}, 'length':[], 'size': size}

        # Start of payload in frame
        spkt = self.FRAGMENT_SKIP_BYTES
	if fragmented == self.FRAGMENT_FRAGN:
            spkt += 1 
        # Start (position) and length in msg
#	smsg = offset << 3   
	length = len(pkt) - spkt

        # Store information
#	self.rcvfragments[stag]['input'][smsg:smsg+length] = pkt[spkt:]
	self.rcvfragments[stag]['input'][offset] = pkt[spkt:]
	self.rcvfragments[stag]['length'].append(length)

	# Check for completion
	total = 0
	for i in self.rcvfragments[stag]['length']:
            total += i
        if total == self.rcvfragments[stag]['size']:
#            msg = self.rcvfragments[stag]['input']
            msg = []
	    for i in sorted(self.rcvfragments[stag]['input']):
	        msg += self.rcvfragments[stag]['input'][i]
	    del self.rcvfragments[stag]
	    self.dispatch(
                signal = 'meshToV6',
                data   = (data[0],msg),
            )
        #return

    def _fragsent_notif(self,sender,signal,data):
        '''
        '''
	stag = data
	size = self.sndfragments[stag]['size']
        tag  = self.sndfragments[stag]['tag']
	for fragment in self.sndfragments[stag]['frag']:
            if not fragment['sent']:
                offset  = fragment['offset']
		payload = []

		#size
		payload.append((size & 0x0700) >> 8)
		payload.append(size & 0x00FF)
		#tag
		payload.append((tag & 0xFF00) >> 8)
		payload.append(tag & 0x00FF)
		#offset & dispatch
		if offset == 0:
                    payload[0] |= self.FRAGMENT_FRAG1 << self.FRAGMENT_DISPATCH
                else:
                    payload[0] |= self.FRAGMENT_FRAGN << self.FRAGMENT_DISPATCH
                    payload.append(offset >> 3)
                #data
                payload += fragment['data']

	        if log.isEnabledFor(logging.DEBUG):
		    log.debug("Sending fragment of " + str(len(payload)) +"B")

		#send it
		self.dispatch(
                    signal = 'bytesToMesh',
		    data   = (self.sndfragments[stag]['nextHop'],payload),
                )

		fragment['sent'] = True
		return
        
	#Message sent
	del self.sndfragments[stag]
	#return
    
    def _fragsent_notif_mote(self,sender,signal,data):
	stag = data[1]
	if stag in self.sndfragments:
            self.dispatch(
                signal = 'fragsent',
                data   = stag,
            )
	else:
 	    if log.isEnabledFor(logging.DEBUG):
	        log.debug("received sending tag {0} from mote".stag)
  	#return

    def _fragabort_notif(self,sender,signal,data):
        '''
        '''

	incoming = data[0]
	stag     = data[1]

	if incoming == 7:
	    if stag in self.rcvfragments:
                del self.rcvfragments[stag]
	elif incoming == 1:
	    if stag in self.sndfragments:
                del self.sndfragments[stag]
	else: #if incoming == 2
	    for msg in self.sndfragments:
	        if str(msg['nextHop']) == tag:
		    del msg
        
        #return 
    
    #======================== helpers =========================================
    
    def _getNewTag(self):
        returnVal = self.tag

	if self.tag == 0xFFFF:
	    self.tag = 0
        else:
	    self.tag += 1

        return returnVal
