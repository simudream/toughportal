#!/usr/bin/env python
#coding=utf-8
import sys,os
from twisted.python import log
from twisted.internet import defer
from twisted.internet import protocol
from twisted.internet import reactor
from toughportal.packet import huawei,cmcc
import socket
import time
import six
import os

class Timeout(Exception):
    """Simple exception class which is raised when a timeout occurs
    while waiting for a ac server to respond."""


def sleep(secs):
    d = defer.Deferred()
    reactor.callLater(secs, d.callback, None)
    return d

class PortalClient(protocol.DatagramProtocol):
    
    results = {}
    
    def __init__(self,secret=six.b(''),timeout=5,retry=5,debug=True,prot='CMCC'):
        self.secret = secret
        self.timeout = timeout
        self.retry = retry
        self.debug=debug
        self.prot=prot
        self.port = reactor.listenUDP(0, self)
        
    def close(self):
        self.transport = None
        self.results.clear()
        self.port.stopListening()

    @defer.inlineCallbacks
    def sendto(self,req,(host,port),recv=True):
        if self.debug:
            print ":: Hexdump >> %s"%hexdump(str(req),len(req))
            
        log.msg(":: Send packet To AC (%s:%s) >> %s"%(host,port,repr(req)))
        
        if not recv:
            self.transport.write(str(req),(host,port))
            return
        
        try:
            for attempt in range(self.retry):
                self.transport.write(str(req),(host,port))
                now = time.time()
                waitto = now + self.timeout
                while now < waitto:
                    if req.sid in self.results:
                        defer.returnValue(self.results.pop(req.sid))
                        return
                    else:
                        now = time.time()
                        yield sleep(0.002)
                        continue
            raise Timeout
        except Exception as err:
            log.err(err,':: Send packet Error (%s:%s) >> %s'%(host, port,str(err)))
            raise err

    def datagramReceived(self, datagram, (host, port)):
        if self.prot == 'CMCC':
            self.processCMCC(datagram, (host, port))
        elif self.prot == 'Huawei':
            self.processHuawei(datagram, (host, port))


    def processCMCC(self, datagram, (host, port)):
        try:
            if self.debug:
                print ":: Hexdump > %s" % cmcc.hexdump(datagram, len(datagram))

            resp = cmcc.PortalV2(packet=datagram, secret=self.secret)
            self.results[resp.sid] = resp
            log.msg(":: Received cmcc packet from AC %s >> %s " % ((host, port), repr(resp)))
        except Exception as err:
            log.err(err, ':: Dropping invalid cmcc packet from %s >> %s' % ((host, port), str(err)))


    def processHuawei(self, datagram, (host, port)):
        try:
            if self.debug:
                print ":: Hexdump > %s" % huawei.hexdump(datagram, len(datagram))

            resp = huawei.PortalV2(packet=datagram, secret=self.secret)
            self.results[resp.sid] = resp
            log.msg(":: Received hw packet from AC %s >> %s " % ((host, port), repr(resp)))

        except Exception as err:
            log.err(err, ':: Dropping invalid hw packet from %s >> %s' % ((host, port), str(err)))
