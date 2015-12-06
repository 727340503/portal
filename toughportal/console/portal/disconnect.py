#!/usr/bin/env python
#coding:utf-8
import sys
import socket
import os.path
import cyclone.auth
import cyclone.escape
import cyclone.web
import binascii
from twisted.python import log
from toughportal.tools import utils
from toughportal.console.portal.base import BaseHandler
from toughportal.packet.cmcc import PortalV2,hexdump
from toughportal.packet import cmcc
from toughportal.listen.cmcc_client import PortalClient
from twisted.internet import defer

class DisconnectHandler(BaseHandler):
    
    @defer.inlineCallbacks
    def get(self):
        try:
            userIp = self.get_argument("wlanuserip")
            sign = self.get_argument("sign")
            if sign != self.mksign(params=[userIp]):
                self.render_json(code=1,msg='sign error')
                return

            cli = PortalClient(secret=self.settings.share_secret)
            rl_req = PortalV2.newReqLogout(userIp,self.settings.share_secret,self.settings.ac_addr[0])
            rl_resp = yield cli.sendto(rl_req,self.settings.ac_addr)
            if rl_resp and rl_resp.errCode > 0:
                log.msg(cmcc.AckLogoutErrs[rl_resp.errCode])
                self.render_json(code=1, msg=cmcc.AckLogoutErrs[rl_resp.errCode])
                return

            log.msg('disconnect success')
            self.render_json(code=0, msg='success')

        except Exception as err:

            log.msg(u"disconnect error %s"%str(err))
            import traceback
            traceback.print_exc()
            self.render_json(code=1, msg='error:%s'%str(err))
            return
        finally:
            cli.close()




        