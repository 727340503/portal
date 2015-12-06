#!/usr/bin/env python
#coding=utf-8

from twisted.internet import defer
from twisted.python import log
from toughportal.console.portal.base import BaseHandler
from toughportal.tools import requests, utils



class IkPingHandler(BaseHandler):
    """
    网关设备与WEB SERVER检测
    请求方式： GET
    示例: http://auth.xxx.com/ping?gwid=123&nasname=TEST&uptime=1000

    gwid	路由ID
    nasname	设备别名
    uptime	单位（秒），系统开机运行时长（重启系统归0）
    """

    def get(self):
        gwid = self.get_argument("gwid", None)
        nasname = self.get_argument("nasname", None)
        uptime = self.get_argument("uptime", None)
        log.msg("ikuai route[%s:%s] ping, uptime %s" % (nasname, gwid, uptime))
        self.write('ok')