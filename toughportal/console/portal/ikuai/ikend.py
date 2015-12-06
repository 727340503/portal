# !/usr/bin/env python
# coding:utf-8

from toughportal.console.portal.base import BaseHandler

class IkEndHandler(BaseHandler):
    """
    所有流程走完以后，返回302重定向到
    完成页面，页面最终显示成功 / 失败的提示效果。
    请求方式： GET
    示例: http: // auth.xxx.com / end?errcode = 10000
    errcode:
    10000	成功
    10001	失败，token效验错误
    10002	失败，参数错误
    20001	失败，验证服务器无响应
    """

    errcodes = {
        "10001": u'认证失败，token效验错误',
        "10002": u"认证失败，参数错误",
        "20001": u"认证失败，验证服务器无响应"
    }

    def get(self):
        errcode = self.get_argument("errcode", None)
        tpl_name = "ikuai_new"
        if errcode == "10000":
            self.render(self.get_index_template(tpl_name))
        else:
            self.syslog.error("ikuai portal auth end error, %s" % errcode)
            self.render_error(msg=self.errcodes.get(errcode, u"未知错误"))