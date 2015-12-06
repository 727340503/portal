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

class LogoutHandler(BaseHandler):
    
    @defer.inlineCallbacks
    def get(self):
        is_chap = self.settings.is_chap
        if not self.current_user:
            self.clear_all_cookies()
            self.redirect("/login")
            return
        try:
            qstr = self.get_secure_cookie("portal_qstr")
            wlan_params = self.get_wlan_params(qstr)
            self.syslog.info("wlan params:" + utils.safestr(wlan_params))
            userIp = wlan_params.get("wlanuserip","")

            cli = PortalClient(secret=self.settings.share_secret)
            rl_req = PortalV2.newReqLogout(
                userIp,self.settings.share_secret,self.settings.ac_addr[0],chap=is_chap)
            rl_resp = yield cli.sendto(rl_req,self.settings.ac_addr)
            if rl_resp and rl_resp.errCode > 0:
                print cmcc.AckLogoutErrs[rl_resp.errCode]
            self.syslog.info('logout success')
        except Exception as err:
            self.syslog.error(u"disconnect error %s" % utils.safestr(err))
            import traceback
            traceback.print_exc()
        finally:
            cli.close()

        self.clear_all_cookies()    
        self.redirect("/login?%s"%(qstr),permanent=False)


        