#!/usr/bin/env python
#coding=utf-8
from toughportal.listen import hw_server,cmcc_server
def run(config):
    if config.get('portal','ac_type') == 'CMCC':
        portal = cmcc_server.PortalListen(config)
        portal.run_normal()
    elif config.get('portal', 'ac_type') == 'Huawei':
        portal = hw_server.PortalListen(config)
        portal.run_normal()