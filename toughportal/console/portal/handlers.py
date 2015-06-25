#!/usr/bin/env python
#coding:utf-8
import sys
import os.path
import cyclone.auth
import cyclone.escape
import cyclone.web
from toughportal.console.portal.base import BaseHandler
from toughportal.console.portal.login import LoginHandler
from toughportal.console.portal.logout import LogoutHandler

class HomeHandler(BaseHandler):
    @cyclone.web.authenticated
    def get(self):
        self.render(self.get_index_template())
        