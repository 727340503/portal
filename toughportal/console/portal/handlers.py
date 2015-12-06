#!/usr/bin/env python
#coding:utf-8
from toughportal.console.portal.base import BaseHandler
from toughportal.console.portal.login import LoginHandler
from toughportal.console.portal.iklogin import IkLoginHandler
from toughportal.console.portal.logout import LogoutHandler
from toughportal.console.portal.disconnect import DisconnectHandler

class HomeHandler(BaseHandler):
    def get(self):
        tpl_name = self.get_argument("tpl_name")
        self.render(self.get_index_template(tpl_name))


class XieyiHandler(BaseHandler):
    def get(self):
        tpl_name = self.get_argument("tpl_name")
        self.render(self.get_xieyi_template(tpl_name))