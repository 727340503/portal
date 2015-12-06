#!/usr/bin/env python
#coding:utf-8
import json
import time
from cyclone import httpclient
from twisted.python import log
from toughportal.tools import utils
from toughportal.console.portal.base import BaseHandler
from toughportal.packet.cmcc import PortalV2,hexdump
from toughportal.packet import cmcc
from toughportal.listen.cmcc_client import PortalClient
from twisted.internet import defer

class PortalError(Exception):pass

class LoginHandler(BaseHandler):


    @defer.inlineCallbacks
    def get(self):
        qstr = self.request.query
        wlan_params = self.get_wlan_params(qstr)
        if self.settings.debug:
            self.syslog.debug("Open portal auth page, wlan params:{0}".format(utils.safestr(wlan_params)))
        tpl = yield self.get_template_attrs(wlan_params.get("ssid", "default"))
        self.render(self.get_login_template(tpl['tpl_name']), msg=None, tpl=tpl, qstr=qstr, **wlan_params)

  
    @defer.inlineCallbacks
    def post(self):
        start_time = time.time()
        secret = self.settings.share_secret
        ac_addr = self.settings.ac_addr
        is_chap = self.settings.is_chap
        qstr = self.get_argument("qstr","")
        wlan_params = self.get_wlan_params(qstr)

        username = self.get_argument("username", None)
        password = self.get_argument("password", None)
        _username = username

        if self.settings.debug:
            self.syslog.debug("Start [username:%s] portal auth, wlan params:%s" % (_username, utils.safestr(wlan_params)))

        userIp = wlan_params.get('wlanuserip','')
        tpl = yield self.get_template_attrs(wlan_params.get("ssid", "default"))
        firsturl = tpl.get("home_page", "/?tpl_name=%s" % tpl.get('tpl_name', 'default'))

        def set_user_cookie():
            self.set_secure_cookie("portal_user", _username, expires_days=1)
            self.set_secure_cookie("portal_logintime", utils.get_currtime(), expires_days=1)
            self.set_secure_cookie("portal_qstr", qstr, expires_days=1)

        @defer.inlineCallbacks
        def get_domain(ssid):
            sign = self.mksign(params=[ssid])
            reqdata = json.dumps(dict(ssid=ssid, sign=sign))
            apiurl = "%s/domain/query" % self.settings.apiurl
            if self.settings.debug:
                self.syslog.debug("start query domain request (%s):  %s" % (apiurl, reqdata))
            resp = yield httpclient.fetch(apiurl,postdata=reqdata, headers={"Content-Type": ["application/json"]})

            jsonresp = json.loads(resp.body)
            if jsonresp['code'] == 1:
                self.syslog.error(jsonresp['msg'])
                defer.returnValue(jsonresp['domain'])
                return

            if jsonresp['code'] == 0:
                if self.settings.debug:
                    self.syslog.debug("query domain success")
                defer.returnValue(jsonresp['domain'])

        def back_login(msg=u''):
            self.render(self.get_login_template(tpl['tpl_name']),tpl=tpl, msg=msg,qstr=qstr, **wlan_params)


        if not username or not password:
            back_login(msg=u"请输入用户名和密码")
            return

        # checkos
        cli_dev, cli_os = self.chk_os
        domain = yield get_domain(wlan_params.get("ssid", "default"))
        username = "%s#%s#%s@%s" % (username, cli_dev, cli_os, domain)


        ####################################################################################
        ## portal chap auth
        ####################################################################################
        @defer.inlineCallbacks
        def chapAuth():
            try:
                cli = PortalClient(secret=secret, syslog=self.syslog)
                rc_req = PortalV2.newReqChallenge(userIp,secret, chap=is_chap)
                rc_resp = yield cli.sendto(rc_req,ac_addr)

                if rc_resp.errCode > 0:
                    if rc_resp.errCode == 2:
                        set_user_cookie()
                        self.redirect(firsturl)
                        return
                    raise PortalError(cmcc.AckChallengeErrs[rc_resp.errCode])

                # req auth
                ra_req = PortalV2.newReqAuth(
                    userIp,
                    username,
                    password,
                    rc_resp.reqId,
                    rc_resp.get_challenge(),
                    secret,
                    ac_addr[0],
                    serialNo=rc_req.serialNo,
                    chap=is_chap
                )
                ra_resp = yield cli.sendto(ra_req,ac_addr)

                if ra_resp.errCode > 0:
                    if ra_resp.errCode == 2:
                        set_user_cookie()
                        self.redirect(firsturl)
                        return
                    _err_msg = "{0},{1}".format(cmcc.AckAuthErrs[ra_resp.errCode], ra_resp.get_text_info()[0] or "")
                    raise PortalError(_err_msg)

                # aff_ack
                aa_req = PortalV2.newAffAckAuth(userIp,secret,ac_addr[0],ra_req.serialNo,rc_resp.reqId, chap=is_chap)
                yield cli.sendto(aa_req,ac_addr,recv=False)

                self.syslog.info('Portal [username:{0}] chap auth success'.format(_username))

                if self.settings.debug:
                    self.syslog.debug('Portal [username:%s] chap auth login [cast:%s ms]' % (
                    _username, (time.time() - start_time) * 1000))

                set_user_cookie()
                self.redirect(firsturl)
            
            except Exception as err:
                try:
                    self.syslog.exception("Portal [username:%s] chap auth catch exception, %s" % (
                    _username, utils.safestr(err.message)))
                    back_login(msg=u"Portal chap auth error,%s" % err.message)
                except:
                    back_login(msg=u"Portal chap auth error,server process error")
            finally:
                cli.close()


        ####################################################################################
        ## portal pap auth
        ####################################################################################
        @defer.inlineCallbacks
        def papAuth():
            try:
                cli = PortalClient(secret=secret, syslog=self.syslog)
                # req auth
                ra_req = PortalV2.newReqAuth(
                    userIp,
                    username,
                    password,
                    0,
                    None,
                    secret,
                    ac_addr[0],
                    chap=False
                )
                ra_resp = yield cli.sendto(ra_req, ac_addr)

                if ra_resp.errCode > 0:
                    if ra_resp.errCode == 2:
                        set_user_cookie()
                        self.redirect(firsturl)
                        return
                    _err_msg = "{0},{1}".format(cmcc.AckAuthErrs[ra_resp.errCode], ra_resp.get_text_info()[0] or "")
                    raise PortalError(_err_msg)

                # aff_ack
                aa_req = PortalV2.newAffAckAuth(userIp, secret, ac_addr[0], ra_req.serialNo, 0, chap=False)
                yield cli.sendto(aa_req, ac_addr, recv=False)

                self.syslog.info('Portal [username:%s] pap auth success' % _username)
                if self.settings.debug:
                    self.syslog.debug('Portal [username:%s] pap auth login [cast:%s ms]' % (
                    _username, (time.time() - start_time) * 1000))

                set_user_cookie()
                self.redirect(firsturl)

            except Exception as err:
                try:
                    self.syslog.error("portal [username:%s] pap auth catch exception,%s" % (
                    _username, utils.safestr(err.message)))
                    back_login(msg=u"portal pap auth error,%s" % utils.safestr(err.message))
                except:
                    back_login(msg=u"portal pap auth error,server process error")
                import traceback
                traceback.print_exc()
            finally:
                cli.close()


        if is_chap:
            yield chapAuth()
        else:
            yield papAuth()

