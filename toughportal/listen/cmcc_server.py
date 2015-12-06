#!/usr/bin/env python
#coding=utf-8
import sys
import time
import os

from twisted.python import log
from twisted.internet import task
from twisted.internet import protocol
from twisted.internet import reactor

from toughportal.packet import cmcc
from toughportal.tools import utils, logger


###############################################################################
# Basic Portal listen                                                      ####
###############################################################################

class PortalListen(protocol.DatagramProtocol):
    
    actions = {}
    
    def __init__(self, config, daemon=False):
        self.syslog = logger.SysLogger(config)
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
        self.ac1 = self.config.get('portal','ac1').split(':')
        self.ac2 = self.config.has_option('portal','ac2') and \
            self.config.get('portal','ac2').split(':') or None
        self.listen_port = self.config.getint('portal','listen')
        self.portal_port = self.config.getint('portal','port')
        self.portal_host = self.config.has_option('portal','host') \
            and self.config.get('portal','host') or '0.0.0.0'
        self.ntf_heart = self.config.getint("portal","ntf_heart")
        try:
            os.environ["TZ"] = self.timezone
            time.tzset()
        except:pass
        
    def init_task(self):
        _task = task.LoopingCall(self.send_ntf_heart)
        _task.start(self.ntf_heart)
    
    def send_ntf_heart(self):
        host,port = self.ac1[0], int(self.ac1[1])
        req = cmcc.PortalV2.newNtfHeart(self.secret,host)
        if self.debug:
            pass
            # self.syslog.info("Send NTF_HEARTBEAT to %s:%s: %s" % (host,port,repr(req)))
        try:
            self.transport.write(str(req), (host,port))
        except:
            pass
        
    def validAc(self,host):
        if host in [self.ac1, '10.10.10.254']:
            return self.ac1
        if self.ac2 and host in self.ac2:
            return self.ac2
            
    def doAckNtfLogout(self,req,(host, port)):
        resp = cmcc.PortalV2.newMessage(
            cmcc.ACK_NTF_LOGOUT,
            req.userIp,
            req.serialNo,
            req.reqId,
            secret = self.secret
        )

        try:
            self.syslog.info("Send portal packet to %s:%s: %s"%(host,port, utils.safestr(req)))
            self.transport.write(str(resp), (host, port))
        except:
            pass
            
    
    def datagramReceived(self, datagram, (host, port)):
        ac = self.validAc(host)
        if not ac:
            return self.syslog.info('Dropping packet from unknown ac host ' + host)
        try:
            req = cmcc.PortalV2(
                secret=self.secret,
                packet=datagram,
                source=(host, port)
            )
            self.syslog.info("Received portal packet from %s:%s: %s"%(host,port,utils.safestr(req)))
            if req.type in self.actions:
                self.actions[req.type](req,(host, port))
            else:
                self.syslog.error('Not support packet from ac host ' + host)
                
        except Exception as err:
            self.syslog.error('Dropping invalid packet from %s: %s' % ((host, port), utils.safestr(err)))
 
    def on_exception(self, err):
        self.syslog.error('Packet process error：%s' % utils.safestr(err))
        
    def run_normal(self):
        log.startLogging(sys.stdout)
        self.syslog.info('portal server listen %s' % self.portal_host)
        reactor.listenUDP(self.listen_port, self,interface=self.portal_host)
        # reactor.run()
            
    def get_service(self):    
        from twisted.application import internet
        return internet.UDPServer(self.listen_port,self,interface=self.portal_host)
        
        
def run(config,is_serrvice=False):
    print 'running portal server...'
    portal = PortalListen(config,daemon=is_serrvice)
    if is_serrvice:
        return portal.get_service()
    else:
        portal.run_normal()


