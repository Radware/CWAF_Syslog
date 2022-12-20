# encoding = utf-8

version = "4.2.1"

import sys
import time
import datetime
import json
import http.client
import re
import getopt
from logging.handlers import SysLogHandler
import logging
import logging.config
import socket
import ssl
import argparse

def getTenantID(credentials,proxy):
    headers = {"Authorization": "Bearer %s" % credentials["Bearer"]}

    try:
        if (proxy['use_proxy']):

            conn = http.client.HTTPSConnection(proxy['address'], proxy['port'])
            conn.set_tunnel("portal-ng.radwarecloud.com", port=443)

        else:
            conn = http.client.HTTPSConnection("portal-ng.radwarecloud.com")

        conn.request("GET", "/v1/users/me/summary", headers=headers)
        response = conn.getresponse()

        data = json.loads(response.read().decode("utf8"))
        if response.status != 200:
            logging.error("Failed TenantID with response => %d : %s", res.status, res.reason)
            logOut(credentials,proxy)
            sys.exit(2)
        else:
            return data["tenantEntityId"]
    except Exception as e:
        print("Error occurred on getting the TenantID from Cloud AppSec portal. {0}".format(str(e)))
        sys.exit(2)


def getApplicationIDs(credentials,proxy):
    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        "requestEntityids": credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        "Content-Type": "application/json;charset=UTF-8",
        "User-Agent": "Python API Syslog %s" % version
    }

    try:
        if (proxy['use_proxy']):

            conn = http.client.HTTPSConnection(proxy['address'], proxy['port'])
            conn.set_tunnel("portal-ng.radwarecloud.com", port=443)

        else:
            conn = http.client.HTTPSConnection("portal-ng.radwarecloud.com")

        conn.request("GET", "/v1/gms/applications", headers=headers)

        response = conn.getresponse()

        if response.status != 200:
            print("Failed collecting application IDs => %d : %s", res.status, res.reason)
            logOut(credentials,proxy)
            exit(2)
        else:
            data = json.loads(response.read().decode("utf8"))
            return data
            
    except Exception as e:
        print("Error occurred collecting application IDs. {0}".format(str(e)))
        sys.exit(2)


def getSessionToken(credentials,proxy):
    if (proxy['use_proxy']):
        conn = http.client.HTTPSConnection(proxy['address'], proxy['port'])
        conn.set_tunnel("radware-public.okta.com", port=443)
    else:
        conn = http.client.HTTPSConnection("radware-public.okta.com")

    payload = "{\"username\":\"" + credentials["email_address"] + "\",\"password\":\"" + credentials["password"] \
              + "\",\"options\":{ \"multiOptionalFactorEnroll\": true,\"warnBeforePasswordExpired\": true}}"
    headers = {'Content-Type': "application/json", 'Accept': 'application/json, text/plain, */*'}

    try:
        conn.request("POST", "/api/v1/authn", payload, headers)
        res = conn.getresponse()
        if res.status != 200:
            logging.error("Failed Session with response => %d : %s", res.status, res.reason)
            sys.exit(2)
        else:
            data = res.read()
            oktadata = json.loads(data.decode("utf-8"))
            credentials["sessionToken"] = oktadata["sessionToken"]
        return 0
    except Exception as e:
        print("Invalid username or password, please verify it.{0}".format(str(e)))
        sys.exit(2)


def getAuthorizationToken(credentials,proxy):
    if (proxy['use_proxy']):
        conn = http.client.HTTPSConnection(proxy['address'], proxy['port'])
        conn.set_tunnel("radware-public.okta.com", port=443)
    else:
        conn = http.client.HTTPSConnection("radware-public.okta.com")

    headers = {"Content-type": "application/json", "Accept": "application/json, text/plain, */*",
               "User-Agent": "Python API Syslog %s" % version}
    conn.request("GET", "/oauth2/aus7ky2d5wXwflK5N1t7/v1/authorize?client_id=M1Bx6MXpRXqsv3M1JKa6" +
                 "&nonce=n-0S6_WzA2M&" +
                 "prompt=none&" +
                 "redirect_uri=https%3A" + "%2F" + "%2F" + "portal-ng.radwarecloud.com" + "%2F" + "&" +
                 "response_mode=form_post&" +
                 "response_type=token&" +
                 "scope=api_scope&" +
                 "sessionToken=" + credentials["sessionToken"] + "&" +
                 "state=parallel_af0ifjsldkj", "", headers)
    res = conn.getresponse()

    if res.status != 200:
        print("{0} : {1}".format(res.status, res.reason))
        sys.exit(2)
    else:
        data = res.read()

        result = re.split('([^;]+);?', res.getheader('set-cookie'), re.MULTILINE)
        for cookie in result:
            dt = re.search(',\sDT=([^;]+);?', cookie, re.MULTILINE)
            sid = re.search(',\ssid=([^;]+);?', cookie, re.MULTILINE)
            proximity = re.search(',(.+=[^;]+);?\sEx', cookie, re.MULTILINE)
            sessID = re.search(r'JSESSIONID=([^;]+);?', cookie, re.MULTILINE)
            if proximity:
                credentials["proximity"] = proximity.group(1)
            elif dt:
                credentials["DT"] = dt.group(1)
            elif sid:
                credentials["sid"] = sid.group(1)
            elif sessID:
                credentials["JSESSIONID"] = sessID.group(1)

        credentials["Bearer"] = data.decode('unicode_escape').split('name="access_token" value="')[1].split('"')[0]

        return 0


def logOut(credentials,proxy):
    if (proxy['use_proxy']):
        conn = http.client.HTTPSConnection(proxy['address'], proxy['port'])
        conn.set_tunnel("radware-public.okta.com", port=443)
    else:
        conn = http.client.HTTPSConnection("radware-public.okta.com")
    headers = {
        'Referer': 'https://portal-ng.radwarecloud.com',
        'Accept': 'application/json, text/plain, */*',
        'Content-Type': 'application/json;charset=UTF-8',
        'Cookie': "JSESSIONID={0},DT={1},sid={2},{3},t=default".format(
            credentials["JSESSIONID"], credentials["DT"], credentials["sid"], credentials["proximity"])
    }
    conn.request("DELETE", "/api/v1/sessions/me", headers=headers)
    res = conn.getresponse()
    data = res.read()

    return data


def getUserActivity(credentials, timelower, timeupper,proxy):
    if (proxy['use_proxy']):
        conn = http.client.HTTPSConnection(proxy['address'], proxy['port'])
        conn.set_tunnel("portal-ng.radwarecloud.com", port=443)
    else:
        conn = http.client.HTTPSConnection("portal-ng.radwarecloud.com")

    payload = '''{"criteria":
                    [{"type":"timeFilter","field":"startDate","includeLower":true,"includeUpper":true,
                        "upper":''' + timeupper + ''',
                        "lower":''' + timelower + '''}],
                    "pagination":{"page":0,"size":100000},
                    "order":[{"type":"Order","order":"DESC","field":"startDate"}]}'''
    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        'requestEntityids': credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        'Content-Length': len(payload),
        'Content-Type': 'application/json;charset=UTF-8',
        "User-Agent": "Python API Syslog %s" % version
    }
    conn.request("POST", "/v1/userActivityLogs/reports/", payload, headers=headers)
    res = conn.getresponse()
    try:
        data = json.loads(res.read())
    except:
        print("No Activity log events to collect for tenant id : {0!s}".format(credentials["TenantID"]))
        print("Response received : {0!s}".format(res))
        return 0
    if res.status == 200:
        return data
    else:
        print(data['message'])
        logOut(credentials,proxy)
        sys.exit(2)


def getSecurityEvents(credentials, timelower, timeupper,proxy,page,more_pages):
    if (proxy['use_proxy']):
        conn = http.client.HTTPSConnection(proxy['proxy_ip'],proxy['proxy_port'])
        conn.set_tunnel("portal-ng.radwarecloud.com", port=443)
    else:
        conn = http.client.HTTPSConnection("portal-ng.radwarecloud.com")

    payload = '''{"criteria":
                    [{"type":"timeFilter","field":"receivedTimeStamp","includeLower":true,"includeUpper":true,
                        "upper":'''+timeupper+''',
                        "lower":'''+timelower+'''}],
                    "pagination":{"page":'''+str(page)+''',"size":100},
                    "order":[{"type":"Order","order":"DESC","field":"receivedTimeStamp","sortingType":"LONG"}]}'''

    headers = {
            "Authorization": "Bearer %s" % credentials["Bearer"],
            'requestEntityids': credentials["TenantID"],
            "Cookie": "Authorization=%s" % credentials["Bearer"],
            'Content-Length': len(payload),
            'Content-Type': 'application/json;charset=UTF-8'
            }
    try:
        conn.request("POST", "/mgmt/monitor/reporter/reports-ext/APPWALL_REPORTS", payload, headers=headers)
        res = conn.getresponse()
        if res.status == 200:
            appdata = json.loads(res.read())
            if int(appdata['metaData']['totalHits']) <= ((page+1)*100) :
                more_pages = True
            else: 
                more_pages = False

            return appdata['data']
        else:
            logging.error("Failed getEvents with response => %d : %s",res.status,res.reason)
            LogOut(credentials)
            exit(2)
    except Exception as e:
        logging.error("Error occurred on getting security events from Cloud AppSec portal-ng. %s",e)
        exit(2)


def getBotEvents(credentials, timelower, timeupper, applicationID,page,proxy):
    app_id=""
    data={}

    if (proxy['use_proxy']):
        conn = http.client.HTTPSConnection(proxy['address'], proxy['port'])
        conn.set_tunnel("portal-ng.radwarecloud.com", port=443)
    else:
        conn = http.client.HTTPSConnection("portal-ng.radwarecloud.com")
    
    if applicationID == "":
        applicationIDs = "\"applicationIds\":[{\"applicationId\":\"" + applicationID +'\"}],'
        print("No application available for the given account : {0!s}".format(applicationIDs))
        return 0

    applicationIDs = "\"applicationIds\":[ {\"applicationId\":\"" + applicationID + '\"}]'

    payload ='''{"applicationIds":[{"applicationId":"''' + applicationID +'''"}],
    "requestParameters":{"sort_order":"desc","page_size":100,"page":''' + page + ''',"starttime":''' + timelower + ''',"endtime":''' + timeupper + '''}}'''

    headers = {
        "Authorization": "Bearer %s" % credentials["Bearer"],
        'requestEntityids': credentials["TenantID"],
        "Cookie": "Authorization=%s" % credentials["Bearer"],
        'Content-Length': len(payload),
        'Content-Type': 'application/json;charset=UTF-8',
        "User-Agent": "Python API Syslog %s" % version
    }

    conn.request("POST", "/antibot/reports/v2/fetch/bad-bot/iia-list", payload, headers=headers)
    res = conn.getresponse()

    if res.status == 502:
        return -1
    elif res.headers["Content-Length"] == "0":
        return 0

    try:
        data = json.loads(res.read())
        if data["page"] == 0:
            return 0
        elif res.status == 200:
            return data["results"]
        else:
            print(data['message'])
            logOut(credentials,proxy)
            sys.exit(2)

    except Exception as e:
        print("Error occurred on getting Bot events from Cloud AppSec portal on application id : %s. %s",
                      applicationIDs, e)
        return -1

def format_activity(bulk_activity, logger, transport):
    item = 0
    build_event = ""

    while item < len(bulk_activity['userActivityLogs']):
        build_event = "_time=" + str(
            datetime.datetime.fromtimestamp(int(bulk_activity['userActivityLogs'][item]['startDate']) / 1000.0)) + ","
        build_event = build_event + "event_type=" + "activity" + ","

        build_event = build_event + "id=" + str(bulk_activity['userActivityLogs'][item]['trackingId']) + ","
        build_event = build_event + "user=" + str(bulk_activity['userActivityLogs'][item]['userEmail']) + ","
        build_event = build_event + "details=" + str(bulk_activity['userActivityLogs'][item]['processTypeText']) + ","

        build_event = build_event + "status=" + str(bulk_activity['userActivityLogs'][item]['status']) + ","

        build_event = build_event + "userIP=" + str(bulk_activity['userActivityLogs'][item]['userIp']) + ","
        build_event = build_event + "country=" + str(bulk_activity['userActivityLogs'][item]['userCountry']) + ","

        build_event = build_event + "user-agent=" + str(bulk_activity['userActivityLogs'][item]['userAgent'])

        if transport == "tcp":
            build_event = build_event + "\n"

        logger.warning(build_event)
        logger.info(build_event)
        logger.handlers[0].flush()
        print(build_event)
        item += 1

    return


def format_bot_event(bulk_events, logger, transport):
    item = 0
    build_event = ""

    while item < len(bulk_events):
        build_event = "_time=" + str(
            datetime.datetime.fromtimestamp(int(bulk_events[item]['time']) / 1000.0)) + ","
        build_event = build_event + "event_type=" + "bot" + ","

        build_event = build_event + "action=" + str(bulk_events[item]['response_code']) + ","
        build_event = build_event + "uri=\"" + str(bulk_events[item]['url']) + "\","

        build_event = build_event + "srcIP=" + str(bulk_events[item]['ip']) + ","
        build_event = build_event + "category=" + str(bulk_events[item]['bot_category']) + ","

        build_event = build_event + "referrer=\"" + str(bulk_events[item]['referrer']) + "\","

        build_event = build_event + "cookie=" + str(bulk_events[item]['session_cookie']) + ","

        build_event = build_event + "violation=" + str(bulk_events[item]['violation_reason']) + ","

        build_event = build_event + "country=" + str(bulk_events[item]['country_code']) + ","

        build_event = build_event + "fqdn=" + str(bulk_events[item]['site']) + ","

        build_event = build_event + "transId=" + str(bulk_events[item]['tid']) + ","

        build_event = build_event + "user-agent=" + str(bulk_events[item]['ua'])

        if transport == "tcp":
            build_event = build_event + "\n"

        logger.warning(build_event)
        logger.info(build_event)
        logger.handlers[0].flush()
        print(build_event)
        item += 1

    return


def format_security_event(bulk_events, logger, transport):
    item = 0
    ua_pattern = 'User-Agent:\s(.+)?'
    referer_pattern = 'Referer:\s(.+)?'
    build_event = ""

    while item < len(bulk_events):

        try:
            if (bulk_events[item]['row']['targetModule'] == "Advanced Rules") or (bulk_events[item]['row']['targetModule'] == "Access-Rules"):

                build_event = "_time=" + str(
                    datetime.datetime.fromtimestamp(
                        int(bulk_events[item]['row']['receivedTimeStamp']) / 1000.0)) + ","

                build_event = build_event + "event_type=" + "security" + ","

                build_event = build_event + "action=" + str(bulk_events[item]['row']['action']) + ","

                build_event = build_event + "uri=" + str(bulk_events[item]['row']['uri']) + ","

                build_event = build_event + "srcIP=" + str(bulk_events[item]['row']['externalIp']) + ","

                build_event = build_event + "srcPort=" + str(bulk_events[item]['row']['sourcePort']) + ","

                build_event = build_event + "method=" + str(bulk_events[item]['row']['method']) + ","

                build_event = build_event + "type=" + str(bulk_events[item]['row']['violationType']) + ","

                build_event = build_event + "severity=" + str(bulk_events[item]['row']['severity']) + ","

                build_event = build_event + "transId=" + str(bulk_events[item]['row']['transId'])

                if 'request' in bulk_events[item]['row']:

                    user_agent = re.search(ua_pattern, bulk_events[item]['row']['request'], re.MULTILINE)

                    if user_agent:
                        build_event = build_event + ",user-agent=" + str(user_agent.group(1))[:-1]

                if 'headers' in bulk_events[item]['row']:

                    referer = re.search(referer_pattern, bulk_events[item]['row']['headers'], re.MULTILINE)

                    if referer:
                        build_event = build_event + ",referer=" + str(referer.group(1))[:-1]

            elif (bulk_events[item]['row']['targetModule'] == "Attackers Feed") or (
                    bulk_events[item]['row']['targetModule'] == "Geo-Blocking"):

                build_event = "_time=" + str(
                    datetime.datetime.fromtimestamp(
                        int(bulk_events[item]['row']['receivedTimeStamp']) / 1000.0)) + ","

                build_event = build_event + "event_type=" + "security" + ","

                build_event = build_event + "action=" + str(bulk_events[item]['row']['action']) + ","

                build_event = build_event + "uri=" + str(bulk_events[item]['row']['uri']) + ","

                build_event = build_event + "srcIP=" + str(bulk_events[item]['row']['externalIp']) + ","

                build_event = build_event + "srcPort=" + str(bulk_events[item]['row']['sourcePort']) + ","

                build_event = build_event + "method=" + str(bulk_events[item]['row']['method']) + ","

                build_event = build_event + "type=" + str(bulk_events[item]['row']['eventType']) + ","

                build_event = build_event + "severity=" + str(bulk_events[item]['row']['severity']) + ","

                build_event = build_event + "transId=" + str(bulk_events[item]['row']['transId'])

                if 'request' in bulk_events[item]['row']:

                    user_agent = re.search(ua_pattern, bulk_events[item]['row']['request'], re.MULTILINE)

                    if user_agent:
                        build_event = build_event + ",user-agent=" + str(user_agent.group(1))[:-1]

                if 'headers' in bulk_events[item]['row']:

                    referer = re.search(referer_pattern, bulk_events[item]['row']['headers'], re.MULTILINE)

                    if referer:
                        build_event = build_event + ",referer=" + str(referer.group(1))[:-1]

            elif bulk_events[item]['row']['violationCategory'] == "HTTP RFC Violations":

                build_event = "_time=" + str(
                    datetime.datetime.fromtimestamp(
                        int(bulk_events[item]['row']['receivedTimeStamp']) / 1000.0)) + ","

                build_event = build_event + "event_type=" + "security" + ","

                build_event = build_event + "action=" + str(bulk_events[item]['row']['action']) + ","

                if 'uri' in bulk_events[item]['row']:
                    build_event = build_event + "uri=" + str(bulk_events[item]['row']['uri']) + ","

                if 'directory' in bulk_events[item]['row']:
                    build_event = build_event + "directory=" + str(bulk_events[item]['row']['directory']) + ","

                build_event = build_event + "appwallTimeStamp=" + str(
                    bulk_events[item]['row']['appwallTimeStamp']) + ","

                build_event = build_event + "dstPort=" + str(bulk_events[item]['row']['destinationPort']) + ","

                build_event = build_event + "srcIP=" + str(bulk_events[item]['row']['externalIp']) + ","

                build_event = build_event + "srcPort=" + str(bulk_events[item]['row']['sourcePort']) + ","

                build_event = build_event + "fqdn=" + str(bulk_events[item]['row']['host']) + ","

                build_event = build_event + "method=" + str(bulk_events[item]['row']['method']) + ","

                build_event = build_event + "module=" + str(bulk_events[item]['row']['module']) + ","

                build_event = build_event + "title=" + str(bulk_events[item]['row']['title']) + ","

                build_event = build_event + "application=" + str(bulk_events[item]['row']['webApp']) + ","

                build_event = build_event + "category=" + str(
                    bulk_events[item]['row']['violationCategory']) + ","

                build_event = build_event + "type=" + str(bulk_events[item]['row']['violationType']) + ","

                build_event = build_event + "severity=" + str(bulk_events[item]['row']['severity']) + ","

                build_event = build_event + "transId=" + str(bulk_events[item]['row']['transId'])

                if bulk_events[item]['row']['request']:

                    user_agent = re.search(ua_pattern, bulk_events[item]['row']['request'], re.MULTILINE)

                    if user_agent:
                        build_event = build_event + ",user-agent=" + str(user_agent.group(1))[:-1]

                    referer = re.search(referer_pattern, bulk_events[item]['row']['request'], re.MULTILINE)

                    if referer:
                        build_event = build_event + ",referer=" + str(referer.group(1))[:-1]

                    cookie = re.search(r'^Cookie:\s(.+)?\r\n', bulk_events[item]['row']['request'],re.MULTILINE)

                    if cookie:
                        build_event = build_event + ",cookie=" + str(cookie.group(1)).replace('Cookie: ', '')

                    x_rdwr_port = re.search(r'^X-RDWR-PORT:\s(.+)?\r\n', bulk_events[item]['row']['request'],re.MULTILINE)

                    if x_rdwr_port:
                        build_event = build_event + ",x-rdwr-port=" + str(
                            x_rdwr_port.group(1)).replace('X-RDWR-PORT: ','')

                    X_RDWR_PORT_MM_ORIG_FE_PORT = re.search(r'^X-RDWR-PORT-MM-ORIG-FE-PORT:\s(.+)?\r\n',
                                                            bulk_events[item]['row']['request'], re.MULTILINE)

                    if X_RDWR_PORT_MM_ORIG_FE_PORT:
                        build_event = build_event + ",x-rdwr-port-mm-orig-fe-port=" + str(
                            X_RDWR_PORT_MM_ORIG_FE_PORT.group(1)).replace('X-RDWR-PORT-MM-ORIG-FE-PORT: ', '')

                    X_RDWR_PORT_MM = re.search(r'^X-RDWR-PORT-MM:\s(.+)?\r\n',
                                               bulk_events[item]['row']['request'],re.MULTILINE)

                    if X_RDWR_PORT_MM:
                        build_event = build_event + ",x-rdwr-port-mm=" + str(X_RDWR_PORT_MM.group(1)).replace(
                            'X-RDWR-PORT-MM: ', '')

            else:

                build_event = "_time=" + str(

                    datetime.datetime.fromtimestamp(
                        int(bulk_events[item]['row']['receivedTimeStamp']) / 1000.0)) + ","

                build_event = build_event + "event_type=" + "security" + ","

                build_event = build_event + "action=" + str(bulk_events[item]['row']['action']) + ","

                build_event = build_event + "directory=" + str(bulk_events[item]['row']['directory']) + ","

                build_event = build_event + "appwallTimeStamp=" + str(
                    bulk_events[item]['row']['appwallTimeStamp']) + ","

                build_event = build_event + "srcIP=" + str(bulk_events[item]['row']['externalIp']) + ","

                build_event = build_event + "dstPort=" + str(bulk_events[item]['row']['destinationPort']) + ","

                build_event = build_event + "srcPort=" + str(bulk_events[item]['row']['sourcePort']) + ","

                build_event = build_event + "fqdn=" + str(bulk_events[item]['row']['host']) + ","

                build_event = build_event + "method=" + str(bulk_events[item]['row']['method']) + ","

                build_event = build_event + "module=" + str(bulk_events[item]['row']['module']) + ","

                build_event = build_event + "title=" + str(bulk_events[item]['row']['title']) + ","

                build_event = build_event + "application=" + str(bulk_events[item]['row']['webApp']) + ","

                build_event = build_event + "category=" + str(
                    bulk_events[item]['row']['violationCategory']) + ","

                build_event = build_event + "type=" + str(bulk_events[item]['row']['violationType']) + ","

                build_event = build_event + "severity=" + str(bulk_events[item]['row']['severity']) + ","

                build_event = build_event + "transId=" + str(bulk_events[item]['row']['transId'])

                if bulk_events[item]['row']['request']:

                    user_agent = re.search(ua_pattern, bulk_events[item]['row']['request'], re.MULTILINE)

                    if user_agent:
                        build_event = build_event + ",user-agent=" + str(user_agent.group(1))[:-1]

                    referer = re.search(referer_pattern, bulk_events[item]['row']['request'], re.MULTILINE)

                    if referer:
                        build_event = build_event + ",referer=" + str(referer.group(1))[:-1]

                    cookie = re.search(r'^Cookie:\s(.+)?\r\n', bulk_events[item]['row']['request'],
                                       re.MULTILINE)

                    if cookie:
                        build_event = build_event + ",cookie=" + str(cookie.group(1)).replace('Cookie: ', '')

                    x_rdwr_port = re.search(r'^X-RDWR-PORT:\s(.+)?\r\n', bulk_events[item]['row']['request'],
                                            re.MULTILINE)

                    if x_rdwr_port:
                        build_event = build_event + ",x-rdwr-port=" + str(x_rdwr_port.group(1)).replace('X-RDWR-PORT: ','')

                    X_RDWR_PORT_MM_ORIG_FE_PORT = re.search(r'^X-RDWR-PORT-MM-ORIG-FE-PORT:\s(.+)?\r\n',
                                                            bulk_events[item]['row']['request'], re.MULTILINE)

                    if X_RDWR_PORT_MM_ORIG_FE_PORT:
                        build_event = build_event + ",x-rdwr-port-mm-orig-fe-port=" + str(X_RDWR_PORT_MM_ORIG_FE_PORT.group(1)).replace('X-RDWR-PORT-MM-ORIG-FE-PORT: ', '')

                    X_RDWR_PORT_MM = re.search(r'^X-RDWR-PORT-MM:\s(.+)?\r\n',
                                               bulk_events[item]['row']['request'],re.MULTILINE)

                    if X_RDWR_PORT_MM:
                        build_event = build_event + ",x-rdwr-port-mm=" + str(X_RDWR_PORT_MM.group(1)).replace(
                            'X-RDWR-PORT-MM: ', '')

            if transport == "tcp":
                build_event = build_event + "\n"

            logger.warning(build_event)
            logger.info(build_event)
            logger.handlers[0].flush()
            print(build_event)
            item += 1
        except Exception as e:
            print("Error occurred with security events from Cloud AppSec portal. {0}".format(str(e)))
            print("Error with event content : {0!s}".format(bulk_events[item]['row']))
            sys.exit(2)
    return


def main(argv):
    page=1
    app_id = 0
    logs_type = {
        "security" : "False",
        "bots" : "False",
        "activity" : "False"
    }
    bulk_activity = ''
    bulk_events={}
    application_IDs = ''
    more_pages=True
    page=0
    proxy= {
        "use_proxy":0,
        "address": "0.0.0.0",
        "port": 0
    }
    args=""
    credentials = {
        "sessionToken": "",
        "Bearer": "",
        "TenantID": "",
        "JSESSIONID": "",
        "DT": "",
        "sid": "",
        "proximity": "",
        'email_address': "",
        'password': ""
    }

    try:
        # Initialize parser
        parser = argparse.ArgumentParser(description="This script collects WAF/Bots/User logs from Radware Cloud WAAP portal. Please call this script as follows :\n%s --security --bots --activity -u <user> -p <password> -i <interval_second> -s <syslog_server> -l <syslog_port> -t <tcp/udp> [-c <SSL_certificate>] [--SSL] [-pa <proxy-address> -pp <proxy-port>]")
        # Adding optional argument
        parser.add_argument('--user', required=True, help = "Your Cloud WAAP API user")
        parser.add_argument("--password", required=True, help="Your Cloud WAAP API password")
        parser.add_argument("--interval", required=True, help="Interval between logs collection")
        parser.add_argument("--server", required=True, help="IP address of your syslog server")
        parser.add_argument("--port", required=True,help="Listening port of your syslog server")
        parser.add_argument("--transport", required=True,  help="Transport protocol, either tcp or udp")
        parser.add_argument("--cert", help="Certificate used with your syslog server")
        parser.add_argument("--ssl", help="Activate SSL encryption with your syslog server")
        parser.add_argument("--proxyAddress", help="IP address of outgoing proxy")
        parser.add_argument("--proxyPort",  help="Port of outgoing proxy")
        parser.add_argument("--waf", action='store_true' ,help="Flag to collect waf security events")
        parser.add_argument("--bots", action='store_true', help="Flag to collect bots events")
        parser.add_argument("--activity", action='store_true', help="Flag to collect user activity logs")

        args = parser.parse_args()

        #opts = getopt.getopt(argv, "hWBAu::p::i::s::l::t::c::S::pa::pp",
#                             ["user=", "password=", "interval=", "server=", "port=", "transport=","proxy-address=","proxy-port="])
    except SystemError as e:
        print(
            'Please call this script as follows :\n%s --security --bots --activity -u <user> -p <password> -i <interval_second> -s '
                '<syslog_server> -l <syslog_port> -t <tcp/udp> [-c <SSL_certificate>] [--SSL] [-pa <proxy-address> -pp <proxy-port>]' %
            sys.argv[0])
        print ("An error occured : %s",e)
        sys.exit(2)

    if (args.proxyPort is not None) ^ (args.proxyAddress is not None):
        print(
            'Please call this script as follows :\n%s --security --bots --activity -u <user> -p <password> -i <interval_second> -s '
            '<syslog_server> -l <syslog_port> -t <tcp/udp> [-c <SSL_certificate>] [--SSL] [-pa <proxy-address> -pp <proxy-port>] ' %
            sys.argv[0])
        sys.exit(2)
    elif (args.proxyPort is not None) and (args.proxyAddress is not None):
        proxy["address"] = args.proxyAddress
        proxy["port"] = args.proxyPort

    credentials['email_address'] = args.user
    credentials['password'] = args.password

    try:
        if args.transport == "udp":
            if args.ssl is not None:
                print("TCP transport is required for SSL encryption.")
                sys.exit(2)
            logger = logging.getLogger()
            syslog = logging.handlers.SysLogHandler(address=(args.server, args.port), socktype=socket.SOCK_DGRAM)
            logger.addHandler(syslog)
        else:  # TCP
            if args.ssl is not None:
                if args.cert is not None:
                    logging.config.dictConfig({
                        'version': 1,
                        'formatters': {
                            'simple': {
                                'format': '%(asctime)s TLS-SYSLOG %(name)s: %(levelname)s %(message)s',
                                'datefmt': '%Y-%m-%dT%H:%M:%S',
                            },
                        },
                        'handlers': {
                            'syslog': {
                                'level': 'INFO',
                                'class': 'tlssyslog.handlers.TLSSysLogHandler',
                                'formatter': 'simple',
                                'address': (args.server, args.port),
                                'ssl_kwargs': {
                                    'cert_reqs': ssl.CERT_REQUIRED,
                                    'ssl_version': ssl.PROTOCOL_TLS,
                                    'ca_certs': args.cert,
                                },
                            },
                        },
                        'loggers': {
                            'Radware_CWAF': {
                                'handlers': ['syslog'],
                                'level': logging.INFO,
                                'propagate': True,
                            },
                        },
                    })
                    logger = logging.getLogger("Radware_CWAF")
                else:
                    print(
                        'Please make sure to define your certificate as follows :\n\
                        %s --security --bots --activity -u <user> -p <password> -i <interval_second> -s '
                        '<syslog_server> -l <syslog_port> -t <tcp/udp> [-c <SSL_certificate>] [--SSL] [-pa <proxy-address> -pp <proxy-port>] ' %
                        sys.argv[0])
                    sys.exit(2)
            else:
                logger = logging.getLogger()
                syslog = logging.handlers.SysLogHandler(address=(args.server, args.port), socktype=socket.SOCK_STREAM)
                logger.addHandler(syslog)

    except Exception as e:
        print("Syslog failed to send to {0!s} ({1!s}/udp): your_text".format(args.server, args.port))
        print(str(e))
        return str(e)

    # Get the session token for the user, using the user and key
    getSessionToken(credentials,proxy)

    # Get the autherization token for the user, using the session token
    getAuthorizationToken(credentials,proxy)
    # Get the tenantID for the user, using the authorization token
    credentials["TenantID"] = getTenantID(credentials,proxy)

    while True:
        try:
            now = int(round(time.time() * 1000))
            past = now - (int(args.interval) * 1000)
            # Retrieve the events list using the authentication token and time filters
            if args.waf == True :
                page=0
                bulk_events = getSecurityEvents(credentials, str(past), str(now),proxy,page,more_pages)
                format_security_event(bulk_events, logger, args.transport)
                while(more_pages == True):
                    bulk_events.clear()
                    page +=1
                    bulk_events=getSecurityEvents(credentials,str(past),str(now),proxy,page,more_pages)
                    if bulk_events :
                        format_security_event(bulk_events, logger, args.transport)
            bulk_events.clear()
            if args.bots == True :
                applicationIDs = getApplicationIDs(credentials,proxy)

                for app_id in applicationIDs["content"] :
                    page=1
                    if app_id["featuresData"]["wafFeatureData"]["protectionConfiguration"]["antibotProtection"]["protectionStatus"] != "DISABLE" :
                        bulk_events=getBotEvents(credentials, str(past), str(now), app_id["id"], str(page), proxy)
                        while (bulk_events != 0):
                            format_bot_event(bulk_events, logger, args.transport)
                            page+=1
                            bulk_events = getBotEvents(credentials, str(past), str(now), app_id["id"], str(page), proxy)
            if args.activity == True :
                bulk_activity = getUserActivity(credentials, str(past), str(now),proxy)
                if (bulk_activity != 0):
                    format_activity(bulk_activity, logger, args.transport)

            time.sleep(interval)

        except KeyboardInterrupt:
            print("Bye. Thanks for using Cloud WAF.")
            logOut(credentials,proxy)
            sys.exit()


if __name__ == "__main__":
    main(sys.argv[1:])
