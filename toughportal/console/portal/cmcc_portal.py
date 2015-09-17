#!/usr/bin/env python
#coding:utf-8
import sys
import os.path
import cyclone.auth
import cyclone.escape
import cyclone.web
from toughportal.console.portal.base import BaseHandler
from toughportal.packet.cmcc import PortalV2, hexdump
from toughportal.packet import cmcc
from toughportal.listen.client import PortalClient
from twisted.internet import defer

class HomeHandler(BaseHandler):
    def get(self):
        self.render(self.get_index_template())


class LoginHandler(BaseHandler):
    def get(self):
        qstr = self.request.query
        wlan_params = self.get_wlan_params(qstr)
        tpl = wlan_params.get("tpl", "default")
        self.render(self.get_login_template(tpl), qstr=qstr, **wlan_params)

    @defer.inlineCallbacks
    def post(self):

        secret = self.settings.share_secret
        ac_addr = self.settings.ac_addr
        is_chap = self.settings.is_chap
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

        ####################################################################################
        ## portal chap auth
        ####################################################################################
        @defer.inlineCallbacks
        def chapAuth():
            try:
                cli = PortalClient(secret=secret)
                rc_req = PortalV2.newReqChallenge(userIp, secret, chap=is_chap)
                rc_resp = yield cli.sendto(rc_req, ac_addr)

                if rc_resp.errCode > 0:
                    if rc_resp.errCode == 2:
                        set_user_cookie()
                        self.redirect(firsturl)
                        return
                    back_login(msg=cmcc.AckChallengeErrs[rc_resp.errCode])
                    return

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
                ra_resp = yield cli.sendto(ra_req, ac_addr)

                if ra_resp.errCode > 0:
                    if ra_resp.errCode == 2:
                        set_user_cookie()
                        self.redirect(firsturl)
                        return
                    back_login(msg="%s,%s" % (cmcc.AckAuthErrs[ra_resp.errCode], ra_resp.get_text_info()[0] or ""))
                    return

                # aff_ack
                aa_req = PortalV2.newAffAckAuth(userIp, secret, ac_addr[0], ra_req.serialNo, rc_resp.reqId,
                                                chap=is_chap)
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
                import traceback
                traceback.print_exc()
            finally:
                cli.close()

        ####################################################################################
        ## portal pap auth
        ####################################################################################
        @defer.inlineCallbacks
        def papAuth():
            try:
                cli = PortalClient(secret=secret)
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
                    back_login(msg="%s,%s" % (cmcc.AckAuthErrs[ra_resp.errCode], ra_resp.get_text_info()[0] or ""))
                    return

                # aff_ack
                aa_req = PortalV2.newAffAckAuth(userIp, secret, ac_addr[0], ra_req.serialNo, 0, chap=False)
                yield cli.sendto(aa_req, ac_addr, recv=False)

                log.msg('auth success')

                set_user_cookie()
                self.redirect(firsturl)

            except Exception as err:
                try:
                    log.msg(u"portal pap auth failure,%s" % err.message)
                    back_login(msg=u"portal pap auth error,%s" % err.message)
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


class LogoutHandler(BaseHandler):
    @defer.inlineCallbacks
    def get(self):
        is_chap = self.settings.is_chap
        if not self.current_user:
            self.clear_all_cookies()
            self.redirect("/login")
            return
        try:
            qstr = self.get_secure_cookie("portal_qstr")
            wlan_params = self.get_wlan_params(qstr)
            log.msg("wlan params:" + repr(wlan_params))
            userIp = wlan_params.get("wlanuserip", "")

            cli = PortalClient(secret=self.settings.share_secret)
            rl_req = PortalV2.newReqLogout(
                userIp, self.settings.share_secret, self.settings.ac_addr[0], chap=is_chap)
            rl_resp = yield cli.sendto(rl_req, self.settings.ac_addr)
            if rl_resp and rl_resp.errCode > 0:
                print cmcc.AckLogoutErrs[rl_resp.errCode]
            log.msg('logout success')
        except Exception as err:
            log.msg(u"disconnect error %s" % str(err))
            import traceback
            traceback.print_exc()
        finally:
            cli.close()

        self.clear_all_cookies()
        self.redirect("/login?%s" % (qstr), permanent=False)