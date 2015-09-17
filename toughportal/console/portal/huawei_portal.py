#!/usr/bin/env python
#coding:utf-8
import sys
import os.path
import cyclone.auth
import cyclone.escape
import cyclone.web
from toughportal.console.portal.base import BaseHandler
from twisted.internet import defer
from toughportal.listen.client import  PortalClient
from toughportal.packet.huawei import PortalV2

class HomeHandler(BaseHandler):
    def get(self):
        self.render(self.get_index_template())

class LoginHandler(BaseHandler):

    def get(self):
        self.render(self.get_login_template())

    @defer.inlineCallbacks
    def post(self):
        secret = self.settings.share_secret
        ac_addr = self.settings.ac_addr
        qstr = self.get_argument("qstr", "")
        wlan_params = self.get_wlan_params(qstr)
        log.msg("wlan params:" + repr(wlan_params))
        userIp = wlan_params.get('wlanuserip', self.request.remote_ip)
        tpl = wlan_params.get("tpl", "default")
        firsturl = "/cmcc"

        def set_user_cookie():
            self.set_secure_cookie("portal_user", username, expires_days=1)
            self.set_secure_cookie("portal_logintime", utils.get_currtime(), expires_days=1)
            self.set_secure_cookie("portal_qstr", qstr, expires_days=1)

        def back_login(msg=u''):
            self.render(self.get_login_template(tpl), msg=msg, qstr=qstr, **wlan_params)

        username = self.get_argument("username", None)
        password = self.get_argument("password", None)
        if not username or not password:
            back_login(msg=u"请输入用户名和密码")
            return

        try:
            cli = PortalClient(secret=secret,prot='Huawei')
            # req info
            ri_req = PortalV2.newReqInfo(userIp, secret)
            ri_resp = yield cli.sendto(ri_req, ac_addr)

            if ri_resp.errCode > 0:
                print portalv2.AckInfoErrs[ri_resp.errCode]

            # req chellenge
            rc_req = PortalV2.newReqChallenge(userIp, secret, serialNo=ri_req.serialNo)
            rc_resp = yield cli.sendto(rc_req, ac_addr)

            if not rc_resp.check_resp_auth(rc_req.auth):
                back_login(msg=u"Challenge响应验证错误，消息被丢弃")
                return

            if rc_resp.errCode > 0:
                if rc_resp.errCode == 2:
                    set_user_cookie()
                    self.redirect("/")
                    return
                back_login(msg=portalv2.AckChallengeErrs[rc_resp.errCode])
                return

            challenge = rc_resp.get_challenge()

            # req auth
            ra_req = PortalV2.newReqAuth(
                userIp,
                username,
                password,
                rc_resp.reqId,
                challenge,
                secret,
                ac_addr[0],
                serialNo=ri_req.serialNo
            )
            ra_resp = yield cli.sendto(ra_req, ac_addr)
            if not ra_resp.check_resp_auth(ra_req.auth):
                back_login(msg=u"认证响应验证错误，消息被丢弃")
                return

            if ra_resp.errCode > 0:
                if rc_resp.errCode == 2:
                    set_user_cookie()
                    self.redirect("/")
                    return
                back_login(msg=u"%s,%s" %(portalv2.AckAuthErrs[ra_resp.errCode],ra_resp.get_text_info()[0] or ""))
                return

            # aff_ack
            aa_req = PortalV2.newAffAckAuth(userIp, secret, ac_addr[0], ra_req.serialNo, rc_resp.reqId)
            yield cli.sendto(aa_req, ac_addr, recv=False)

            log.msg('auth success')

            set_user_cookie()
            self.redirect(firsturl)

        except Exception as err:
            try:
                log.msg(u"portal chap auth failure,%s" % err.message)
                back_login(msg=u"portal chap auth error,%s" % err.message)
            except:
                back_login(msg=u"portal chap auth error,server process error")
        finally:
            cli.close()


class LogoutHandler(BaseHandler):
    @defer.inlineCallbacks
    def get(self):
        if not self.current_user:
            self.clear_all_cookies()
            self.redirect("/cmcc/login")
            return
        try:
            cli = PortalClient(secret=self.settings.share_secret,prot='Huawei')
            rl_req = PortalV2.newReqLogout(
                self.request.remote_ip, self.settings.share_secret, self.settings.ac_addr[0])
            rl_resp = yield cli.sendto(rl_req, self.settings.ac_addr)
            if rl_resp and rl_resp.errCode > 0:
                print portalv2.AckLogoutErrs[rl_resp.errCode]
            log.msg('logout success')
        except Exception as err:
            print (u"disconnect error %s" % str(err))
            import traceback
            traceback.print_exc()
        finally:
            cli.close()

        self.clear_all_cookies()
        self.redirect("/cmcc/login", permanent=False)
