#!/usr/bin/env python
# coding:utf-8
from twisted.internet import defer
from toughportal.console.portal.base import IKBaseHandler
import time

class IkLoginHandler(IKBaseHandler):

    @defer.inlineCallbacks
    def get(self):

        gwid = self.get_argument("gwid", "")
        mac = self.get_argument("mac", "")
        if not gwid:
            self.render_error(msg=u"无效的gwid")
            return

        domain = yield self.get_domain(gwid)

        if not domain:
            self.render_error(msg=u"gwid未在系统注册")
            return

        tpl = yield self.get_ik_template_attrs(gwid)
        self.render(self.get_login_template(tpl.get('ikuai_template', "ikuai")),
                    msg=None,
                    tpl=tpl,
                    qstr='',
                    domain=domain,
                    mac=mac)


    def post(self, *args, **kwargs):
        start_time = time.time()
        username = self.get_argument("username", None)
        password = self.get_argument("password", None)
        domain = self.get_argument("domain", None)
        mac = self.get_argument("mac", None)
        nasaddr = '0.0.0.0'
        vlanid1, vlanid2 = 0, 0
        cli_dev, cli_os = self.chk_os
        isChap = 0
        chapId = 0
        chapPasswdHex = 'null'
        challengeHex = 'null'

        reqdata = dict(
            username=username,
            password=password,
            domain=domain,
            macaddr=mac,
            nasaddr=nasaddr,
            vlanid1=vlanid1,
            vlanid2=vlanid2,
            deviceType=cli_dev,
            os=cli_os,
            isChap=isChap,
            chapId=chapId,
            chapPasswdHex=chapPasswdHex,
            challengeHex=challengeHex,
        )

        resp = yield self.policy_auth(reqdata)
        if self.settings.debug:
            self.syslog.debug('ikportal login cast:%s' % (time.time() - start_time))

        self.render_json(**resp)
