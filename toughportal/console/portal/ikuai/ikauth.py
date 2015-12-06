# !/usr/bin/env python
# coding:utf-8
from twisted.internet import defer
from toughportal.console.portal.base import IKBaseHandler
from toughportal.tools import requests, utils
from hashlib import md5
import json
import time
import base64
import urlparse
import urllib


class IkAuthHandler(IKBaseHandler):
    """
    用户打开任意网站时，自动跳转到Portal首页
    请求方式: GET
    示例: http://auth.xxx.com/index/? ver=1&enc= base64&refer=base64
    ver        参数版本号
    enc        参数封装（使用Base64转换）
    refer         跳转源URL地址（使用Base64转换）

    enc参数:
        gwid	路由唯一ID
        nasname 	设备别名，针对别名做不同策略方案
        callback_url	网关回调地址，如：callback_url=http://1.0.0.0/callback    详解见 2.2.2
        user_ip		客户端IP
        mac		客户端MAC
        router_ver	路由版本
        bssid		AP的无线MAC（只有爱快的AP支持）
        apmac	APMAC（只有爱快的AP支持）
        ssid	SSID名称（只有爱快的AP支持）
        timestamp	时间戳

    ---------------------------------------------------------------------------------------

    WEB SERVER 验证成功以后，调用callback_url 地址放行客户端
    请求方式: GET
    示例:  http://1.0.0.0/callback?ver=1&enc=base64&token=32位MD5&end_url=http://auth.xxx.com/end

    token计算：

    enc内的所有参数 + API私钥 计算出一个MD5值，如： token=md5(“mac=123&user_ip=234&key=123456789”)
    注意：传参数的时候不能把key也加入，KEY 只是在计算 token时使用。

    end_url ：
    完成所有流程以后，最终跳转到该URL，

    enc参数, 《不能有空格和特殊字符 ; | ‘ “ &》 :

        user_id	用户名，可以为空
        user_ip	客户端IP
        mac	客户端MAC，需小写mac地址,如：00:aa:bb:cc:dd:ee
        upload	上传速率，单位KB，>= 0的正整数，0表示不限速。如：upload=512
        download	下载速率，单位KB，>= 0的正整数，0表示不限速。如：download=2048
        phone		手机号码，可以为空
        name		姓名，可以为空
        comment	备注，可以为空
        type	类型，如： 微信认证，手机认证，QQ认证,这个名称自己定义
        session_id	如果开启二次验证功能，或者需要使用踢下线功能，那么该选项不能为空，否则无法踢下线和二次验证.
        timestamp	时间戳，双方服务器的时间 相差不能超过 5 分钟
    """

    @defer.inlineCallbacks
    def get(self):

        ver = self.get_argument("ver", 1)
        enc_b64 = self.get_argument("enc", None)
        refer = self.get_argument("refer", None)

        if not enc_b64:
            self.render_error(msg=u"缺少参数enc")
            return

        params = urlparse.parse_qs(base64.decodestring(enc_b64))
        enc_dict = {k: params[k][0] for k in params}

        gwid = enc_dict["gwid"]
        mac = enc_dict["mac"]
        # nasname = enc_dict["nasname"]
        callback_url = enc_dict["callback_url"]
        user_ip = enc_dict["user_ip"]
        # router_ver = enc_dict["router_ver"]
        # bssid = enc_dict["bssid"]
        # apmac = enc_dict["apmac"]
        # ssid = enc_dict["ssid"]
        # timestamp = enc_dict["timestamp"]

        if not gwid:
            self.render_error(msg=u"无效的设备gwid")
            return

        domain = yield self.get_domain(gwid)

        if not domain:
            self.render_error(msg=u"设备gwid未在系统注册")
            return

        tpl = yield self.get_ik_template_attrs(gwid)
        self.render(self.get_login_template(tpl.get('tpl_name')),
                    msg=None,
                    tpl=tpl,
                    qstr='',
                    domain=domain,
                    mac=mac,
                    refer=refer,
                    user_ip=user_ip,
                    gwid=gwid,
                    callback_url=callback_url)


    @defer.inlineCallbacks
    def post(self, *args, **kwargs):
        start_time = time.time()
        username = self.get_argument("username", None)
        password = self.get_argument("password", None)
        domain = self.get_argument("domain", None)
        mac = self.get_argument("mac", None)
        vlanid1, vlanid2 = 0, 0
        cli_dev, cli_os = self.chk_os
        isChap = 0
        chapId = 0
        chapPasswdHex = 'null'
        challengeHex = 'null'

        gwid = self.get_argument("gwid")
        user_ip = self.get_argument("user_ip")
        end_url = "{0}://{1}/ikend".format(self.request.protocol, self.request.host)
        callback_url = self.get_argument("callback_url")

        iknas = yield self.get_ikuai_nas(gwid)
        nasaddr = iknas.get("nas_addr", '0.0.0.0')

        reqdata = dict(
            userName=username,
            password=password,
            domain=domain,
            macAddr=mac,
            nasAddr=nasaddr,
            vlanId1=vlanid1,
            vlanId2=vlanid2,
            deviceType=cli_dev,
            os=cli_os,
            isChap=isChap,
            chapId=chapId,
            chapPasswdHex=chapPasswdHex,
            challengeHex=challengeHex,
        )

        jsonresp = yield self.policy_auth(reqdata, test=False)
        if jsonresp['code'] == 1:
            self.render_error(msg=jsonresp['msg'])
            return

        if self.settings.debug:
            self.syslog.debug('ikauth login cast:%s' % (time.time() - start_time))

        cparams = dict(
            user_id=username,
            user_ip=user_ip,
            upload=0,
            download=0,
            phone='',
            name='',
            comment='',
            type='portal',
            session_id=utils.get_uuid(),
            timestamp=int(time.time())
        )

        session = dict(
            username=username,
            nas_addr=nasaddr,
            session_id=cparams["session_id"],
            start_time=utils.get_currtime(),
            ipaddr=user_ip,
            macaddr=mac,
            input_total=0,
            output_total=0
        )
        session['sign'] = self.mksign(session.values())
        _apiurl = "%s/session/add" % self.settings.apiurl
        se_resp = yield requests.post(_apiurl,
                                      data=json.dumps(session, ensure_ascii=False),
                                      headers={"Content-Type": ["application/json"]})
        if se_resp.code != 200:
            self.syslog.error("ikuai session create error : {0}".format(repr(se_resp)))
            self.render_error(msg=u"认证失败,创建会话失败")
            return


        param_str = urllib.urlencode(cparams)
        param_str = "{0}&mac={1}".format(param_str, mac)
        token = md5("{0}&key={1}".format(param_str, iknas.get('api_key'))).hexdigest()
        enc = base64.encodestring(param_str)

        full_url = "{0}?ver=1&enc={1}&token={2}&end_url={3}".format(callback_url.strip(), enc, token, end_url)
        self.syslog.info("[username:{0}] callback {1}".format(username, full_url))

        if self.settings.debug:
            self.syslog.debug('ikportal auth cast:%s' % (time.time() - start_time))

        self.redirect(full_url)