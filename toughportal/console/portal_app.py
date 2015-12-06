#!/usr/bin/env python
#coding:utf-8
import sys
import cyclone.web
from cyclone import httpclient
from twisted.python import log
from twisted.internet import reactor, defer
from twisted.internet import task
from toughportal.tools import utils,logger
from toughportal.console.portal import handlers
from toughportal.console.portal import roslogin
from toughportal.console.portal.ikuai import ikauth, ikverify, ikend, ikping
from beaker.cache import CacheManager
from beaker.util import parse_cache_config_options
from mako.lookup import TemplateLookup
from hashlib import md5
import toughportal
import time
import json
import os

###############################################################################
# portal web application                                                                 
###############################################################################
class Application(cyclone.web.Application):
    def __init__(self,**kwargs):
        _handlers = [
            (r"/", handlers.HomeHandler),
            (r"/xieyi", handlers.XieyiHandler),
            (r"/login", handlers.LoginHandler),
            (r"/logout", handlers.LogoutHandler),
            (r"/dm", handlers.DisconnectHandler),
            (r"/iklogin", handlers.IkLoginHandler),
            (r"/ikauth", ikauth.IkAuthHandler),
            (r"/ikverify", ikverify.IkVerifyHandler),
            (r"/ikping", ikping.IkPingHandler),
            (r"/ikend", ikend.IkEndHandler),
            (r"/roslogin", roslogin.LoginHandler),
        ]
        
        server = kwargs.pop("server")
        self.syslog = server.syslog
        self.check_os_funcs = server.admin_task.check_os_funcs

        settings = dict(
            cookie_secret="12oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            login_url="/login",
            template_path=os.path.join(os.path.dirname(__file__), "portal/views"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            pftp_template_path=os.path.join(os.path.dirname(toughportal.__file__), "pftp/views"),
            pftp_static_path=os.path.join(os.path.dirname(toughportal.__file__), "pftp/res"),
            xsrf_cookies=True,
            debug=kwargs.get("debug",False),
            xheaders=True,
            share_secret=server.share_secret,
            is_chap=server.is_chap,
            ac_addr=(server.ac1[0],int(server.ac1[1])),
            api_secret=kwargs.get("api_secret", False),
            apiurl=kwargs.get("apiurl", False),
        )

        self.cache = CacheManager(**parse_cache_config_options({
            'cache.type': 'file',
            'cache.data_dir': '/tmp/cache/data',
            'cache.lock_dir': '/tmp/cache/lock'
        }))

        self.tp_lookup = TemplateLookup(directories=[settings['template_path'], settings['pftp_template_path']],
                                        default_filters=['decode.utf8'],
                                        input_encoding='utf-8',
                                        output_encoding='utf-8',
                                        encoding_errors='replace',
                                        module_directory="/tmp/portal")

        _handlers.append((r"/res", cyclone.web.StaticFileHandler, {"path": settings['pftp_static_path']}))
        
        cyclone.web.Application.__init__(self, _handlers, **settings)

class AdminTask:

    def __init__(self,server):
        self.syslog = server.syslog
        self.server = server
        self.check_os_funcs = []
        self.start()

    def start(self):
        self.syslog.info('start admin check task...')
        _task = task.LoopingCall(self.ping)
        _task.start(120)
        _task2 = task.LoopingCall(self.load_ostypes)
        _task2.start(3600)

    def mksign(self, params=[]):
        _params = [str(p) for p in params if p is not None]
        _params.sort()
        _params.insert(0, self.server.api_secret)
        strs = ''.join(_params)
        if self.server.debug:
            log.msg("sign_src = %s" % strs)
        return md5(strs.encode()).hexdigest().upper()

    def on_ping(self,resp):
        if self.server.debug:
            log.msg(resp.body)

        if resp.code != 200:
            self.syslog.error("ping admin server error,http status = %s" % resp.code)
            return

        jsonresp = json.loads(resp.body)
        if jsonresp['code'] == 0:
            if self.server.debug:
                self.syslog.debug("ping admin success")

        elif jsonresp['code'] == 1:
            self.syslog.error("ping admin server error, %s" % jsonresp['msg'])

        elif jsonresp['code'] == 100:
            self.add_portal()


    def ping(self):
        sign = self.mksign(params=[self.server.portal_name, self.server.portal_addr])
        reqdata = json.dumps(dict(name=self.server.portal_name, ip_addr=self.server.portal_addr, sign=sign))

        if self.server.debug:
            self.syslog.debug("register portal request: %s" % reqdata)

        d = httpclient.fetch("%s/portal/ping" % self.server.apiurl,
                             postdata=reqdata, headers={"Content-Type": ["application/json"]})
        d.addCallback(self.on_ping)

    def on_add_portal(self,resp):
        if self.server.debug:
            log.msg(resp.body)

        if resp.code != 200:
            self.syslog.error("register portal to admin server error,http status = %s" % resp.code)
            return

        jsonresp = json.loads(resp.body)

        if jsonresp['code'] == 0:
            self.syslog.info("register portal success")

        elif jsonresp['code'] == 1:
            self.syslog.error("register portal server error, %s" % jsonresp['msg'])

    def add_portal(self):
        sign = self.mksign(params=[
            self.server.portal_name,
            self.server.portal_addr,
            self.server.admin_listen,
            self.server.api_secret,
            self.server.port,
            self.server.listen,
            self.server.ac1[0]
        ])
        reqdata = json.dumps(dict(
            name=self.server.portal_name,
            ip_addr=self.server.portal_addr,
            admin_port=self.server.admin_listen,
            secret=self.server.api_secret,
            http_port=self.server.port,
            listen_port=self.server.listen,
            ac_server=self.server.ac1[0],
            sign=sign
        ))
        if self.server.debug:
            self.syslog.debug("register portal request:  %s" % reqdata)
        d = httpclient.fetch("%s/portal/add" % self.server.apiurl,
                             postdata=reqdata, headers={"Content-Type": ["application/json"]})

        d.addCallback(self.on_add_portal)

    def load_ostypes(self):
        sign = self.mksign(params=[self.server.portal_name])
        reqdata = json.dumps(dict(name=self.server.portal_name, sign=sign))
        if self.server.debug:
            self.syslog.debug("Start query os types request:  %s" % reqdata)
        d = httpclient.fetch("%s/ostype/query" % self.server.apiurl,
                             postdata=reqdata, headers={"Content-Type": ["application/json"]})
        d.addCallback(self.on_load_ostypes)

    def on_load_ostypes(self,resp):
        import re
        if self.server.debug:
            self.syslog.debug("query os types resp {}".format(resp.body))
        if resp.code != 200:
            self.syslog.error("query os types from admin server error,http status = %s" % resp.code)
            return
        jsonresp = json.loads(resp.body)
        if jsonresp['code'] == 1:
            self.syslog.error("query os types error, %s" % jsonresp['msg'])

        self.check_os_funcs = []
        for os_name,dev_type,rule in jsonresp['rules']:
            self.check_os_funcs.append([dev_type, os_name, re.compile(r'{0}'.format(rule), re.IGNORECASE)])


###############################################################################
# portal web server                                                                 
###############################################################################
class PortalServer(object):

    def __init__(self,config):
        self.config = config
        self.syslog = logger.SysLogger(config)
        self.init_config()
        self.init_timezone()
        self.admin_task = AdminTask(self)
        self.web_factory = Application(
            server=self,
            debug=self.debug,
            api_secret=self.api_secret,
            apiurl=self.apiurl,
        )
        
    def init_config(self):
        """ 初始化配置
        """
        self.portal_name = os.environ.get("PORTAL_NAME", self.config.get('portal', 'name'))
        self.portal_addr = os.environ.get("PORTAL_ADDR", self.config.get('portal', 'ipaddr'))
        self.logfile = self.config.get('portal','logfile')
        self.secret = os.environ.get("SECRET", self.config.get('DEFAULT', 'secret'))
        self.timezone = os.environ.get("TIMEZONE", self.config.get('DEFAULT', 'tz') or 'CST-8')
        self.debug = self.config.getboolean('DEFAULT','debug')
        self.listen = self.config.getint('portal', 'listen')
        self.port = self.config.getint('portal','port')
        self.host = self.config.has_option('portal','host') \
            and self.config.get('portal','host') or '0.0.0.0'
        self.share_secret = self.config.get('portal','secret')
        self.is_chap = self.config.getboolean('portal', 'chap')
        self.ac1 = os.environ.get("AC_SERVER", self.config.get('portal', 'ac1')).split(':')
        self.ac2 = self.ac1
        self.apiurl = os.environ.get("ADMIN_URL", self.config.get('admin', 'apiurl'))
        self.api_secret = os.environ.get("ADMIN_SECRET", self.config.get('admin', 'secret'))
        self.admin_listen = int(os.environ.get("ADMIN_PORT", self.config.get('admin', 'listen')))

        # update aescipher
        utils.aescipher.setup(self.secret)
        self.encrypt = utils.aescipher.encrypt
        self.decrypt = utils.aescipher.decrypt
    
    def init_timezone(self):
        """ 时区初始化
        """
        try:
            os.environ["TZ"] = self.timezone
            time.tzset()
        except:pass



    def run_normal(self):
        """ 运行服务
        """
        log.startLogging(sys.stdout)
        self.syslog.info('portal web server listen %s'%self.host)
        reactor.listenTCP(self.port, self.web_factory,interface=self.host)


def run(config):
    print 'running portal server...'
    portal = PortalServer(config)
    portal.run_normal()
