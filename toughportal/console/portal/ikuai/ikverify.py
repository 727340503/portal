# !/usr/bin/env python
# coding:utf-8
from twisted.internet import defer
from twisted.python import log
from toughportal.console.portal.base import BaseHandler
from toughportal.tools import requests, utils
import json

class IkVerifyHandler(BaseHandler):
    """
    回调接口根据配置的需求会请求 WEB SERVER，验证session_id 是否合法。
    该验证方式不是客户端请求，是爱快系统后台请求。
    WEB SERVER 对session_id 的验证应该有一个超时，一般 10~30秒足够。
    请求方式：  GET
    User-Agent： Webauth
    示例:  http://auth.xxx.com/auth?session_id=123456789
    返回值：
        20000	成功
        20001	失败（对接方自定义错误内容）
        ….	失败（对接方自定义错误内容）
    """

    @defer.inlineCallbacks
    def get(self):
        session_id = self.get_argument("session_id", None)
        if not session_id:
            self.write('20001')

        sign = self.mksign([session_id])
        apiurl = "%s/session/exists" % self.settings.apiurl
        reqdata = json.dumps(dict(session_id=session_id,sign=sign), ensure_ascii=False)
        headers = {"Content-Type": ["application/json"]}
        resp = yield requests.post(apiurl, data=reqdata, headers=headers)
        if resp.code != 200:
            self.syslog.error("ikuai session exists error : {0}".format(repr(resp)))
            self.write("20001")
            return

        jsonresp = yield resp.json()
        if jsonresp['code'] == 1:
            self.syslog.error("ikuai session exists error : {0}".format(utils.safestr(jsonresp['msg'])))
            self.write("20001")
            return

        self.write('20000')



