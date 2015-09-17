#!/usr/bin/env python
#coding=utf-8
import sys,os
import ConfigParser
from twisted.python.logfile import DailyLogFile
from twisted.python import log
from twisted.internet import task
from twisted.internet.defer import Deferred
from twisted.internet import protocol
from twisted.internet import reactor
from toughportal.packet import cmcc
import datetime
import logging
import socket
import time
import six
import os

        
###############################################################################
# Basic Portal listen                                                      ####
###############################################################################

class PortalListen(protocol.DatagramProtocol):
    
    actions = {}
    
    def __init__(self, config,daemon=False):
        self.config = config
        self.daemon = daemon
        self.init_config()
        self.actions = {
            cmcc.NTF_LOGOUT : self.doAckNtfLogout
        }
        reactor.callLater(5,self.init_task)
        
    def init_config(self):
        self.logfile = self.config.get('portal','logfile')
        self.secret = self.config.get('portal','secret')
        self.timezone = self.config.get('DEFAULT','tz') or "CST-8"
        self.debug = self.config.getboolean('DEFAULT','debug')
        self.ac = self.config.get('portal','ac1').split(':')
        self.listen_port = self.config.getint('portal','listen')
        self.portal_port = self.config.getint('portal','port')
        self.portal_host = self.config.has_option('portal','host') \
            and self.config.get('portal','host') or  '0.0.0.0'
        self.ntf_heart = self.config.getint("portal","ntf_heart")
        try:
            os.environ["TZ"] = self.timezone
            time.tzset()
        except:pass
        
    def init_task(self):
        _task = task.LoopingCall(self.send_ntf_heart)
        _task.start(self.ntf_heart)
    
    def send_ntf_heart(self):
        host,port = self.ac[0], int(self.ac[1])
        req = cmcc.PortalV2.newNtfHeart(self.secret,host)
        log.msg(":: Send NTF_HEARTBEAT to %s:%s: %s"%(host,port,repr(req)),level=logging.INFO)
        try:
            self.transport.write(str(req), (host,port))
        except:
            pass
        
    def validAc(self,host):
        return  host in self.ac1
            
    def doAckNtfLogout(self,req,(host, port)):
        resp = cmcc.PortalV2.newMessage(
            cmcc.ACK_NTF_LOGOUT,
            req.userIp,
            req.serialNo,
            req.reqId,
            secret = self.secret
        )

        try:
            log.msg(":: Send portal packet to %s:%s: %s"%(host,port,repr(req)),level=logging.INFO)
            self.transport.write(str(resp), (host, port))
        except:
            pass
            
    
    def datagramReceived(self, datagram, (host, port)):
        if not self.validAc(host):
            return log.msg(':: Dropping packet from unknown ac host ' + host,level=logging.INFO)
        try:
            req = cmcc.PortalV2(
                secret=self.secret,
                packet=datagram,
                source=(host, port)
            )
            log.msg(":: Received portal packet from %s:%s: %s"%(host,port,repr(req)),level=logging.INFO)
            if req.type in self.actions:
                self.actions[req.type](req,(host, port))
            else:
                log.msg(':: Not support packet from ac host ' + host,level=logging.INFO)
                
        except Exception as err:
            log.err(err,':: Dropping invalid packet from %s: %s'%((host, port),str(err)))
 
    def on_exception(self,err):
        log.msg(':: Packet process error：%s' % str(err))   
        
    def run_normal(self):
        if self.debug:
            log.startLogging(sys.stdout)
        else:
            log.startLogging(DailyLogFile.fromFullPath(self.logfile))
        log.msg('portal server listen %s'%self.portal_host)  
        reactor.listenUDP(self.listen_port, self,interface=self.portal_host)
        # reactor.run()
        
        
def run(config,is_serrvice=False):
    print 'running cmcc portal server...'
    portal = PortalListen(config)
    portal.run_normal()


