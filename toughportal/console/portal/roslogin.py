#!/usr/bin/env python
# coding:utf-8

from toughportal.console.portal.base import BaseHandler
from twisted.internet import defer


class PortalError(Exception): pass


class LoginHandler(BaseHandler):

    @defer.inlineCallbacks
    def get(self):

        authurl = self.get_argument("authurl")
        ssid = self.get_argument("ssid", 'default')
        if not authurl:
            self.render_error(msg=u"无效的认证请求")

        if self.settings.debug:
            self.syslog.debug("open ros portal auth page")

        tpl = yield self.get_template_attrs(ssid)
        self.render(self.get_login_template(tpl['tpl_name']), msg=None, tpl=tpl, qstr='', authurl=authurl)
