#!/usr/bin/python3
#
#    ToDo:
#       improve error handling
#       session persistence
#       logging enhance - timestamp, output to file
#

import sys
import argparse
import re
import json
import urllib
import urllib.parse as urlparse
from datetime import datetime
from time import sleep
import pandas as pd
from bs4 import BeautifulSoup
import traceback
import requests
import getpass
import mylogger as log
import importlib

pd.set_option('display.max_columns', 100)
pd.set_option('display.width', 1000)

portalDomainList = {
    "internal": "internal-portal.central.arubanetworks.com",
    "us-1": "portal.central.arubanetworks.com",                 # prod
    "us-2": "portal-prod2.central.arubanetworks.com",           # central-prod2
    "us-west4": "portal-uswest4.central.arubanetworks.com",     # uswest4
    "eu-1": "portal-eu.central.arubanetworks.com",              # eu
    "eu-central3": "portal-eucentral3.central.arubanetworks.com",  # eucentral3
    "apac-1": "portal-apac.central.arubanetworks.com",          # apac
    "apac-east1": "portal-apaceast.central.arubanetworks.com",  # apaceast
    "apac-south1": "portal-apacsouth.central.arubanetworks.com",  # apacsouth
    "canada-1": "portal-ca.central.arubanetworks.com",          # starman
    "china-1": "portal.central.arubanetworks.com.cn",           # china-prod
}
uiDomainList = {
    "internal": "internal-ui.central.arubanetworks.com",
    "us-1": "app.central.arubanetworks.com",
    "us-2": "app-prod2-ui.central.arubanetworks.com",
    "us-west4": "app-uswest4.central.arubanetworks.com",
    "eu-1": "app2-eu.central.arubanetworks.com",
    "eu-central3": "app-eucentral3.central.arubanetworks.com",
    "apac-1": "app2-ap.central.arubanetworks.com",
    "apac-east-1": "app-apaceast.central.arubanetworks.com",
    "apac-south1": "app-apacsouth.central.arubanetworks.com",
    "canada-1": "app-ca-ui.central.arubanetworks.com",
    "china-1": "app.central.arubanetworks.com.cn",
}
apigwDomainList = {
    "internal": "internal-apigw.central.arubanetworks.com",
    "us-1": "app1-apigw.central.arubanetworks.com",
    "us-2": "apigw-prod2.central.arubanetworks.com",
    "us-west4": "apigw-uswest4.central.arubanetworks.com",
    "eu-1": "eu-apigw.central.arubanetworks.com",
    "eu-central3": "apigw-eucentral3.central.arubanetworks.com",
    "apac-1": "api-ap.central.arubanetworks.com",
    "apac-east-1": "apigw-apaceast.central.arubanetworks.com",
    "apac-south1": "apigw-apacsouth.central.arubanetworks.com",
    "canada-1": "apigw-ca.central.arubanetworks.com",
    "china-1": "apigw.central.arubanetworks.com.cn",
}

########################
#   utility functions
########################
def get_mkeys(dic, *args):
    arg = [*args]
    return (dic[k] for k in arg)


def root_cause(e):
    rc = e
    while rc.__context__ is not None:
        rc = rc.__context__
    return rc


########################
#   Main class
########################
class CentralSession:
    """
    Manages Central session
    HTTP session for UI/API, API I/F, API tokens
    """
    def __init__(self, instname, username, password='', customerid='', appname=''):
        self.uiSes = requests.Session()         # session for Central UI (Portal/NMS App)
        self.apiSes = requests.Session()        # session for Central API
        self.accToken = ""
        self.refToken = ""
        self.username = username
        self.password = password
        self.instname = instname.lower()
        self.customerId = customerid
        self.appName = appname
        self.clientId = ""
        self.clientSecret = ""
        self.nmsLogin = False
        self.apiLogin = False
        self.tokenCacheFile = 'tokens.txt'

        if instname not in portalDomainList:
            log.err(f"Invalid Central instance: {instname}")
            sys.exit(-1)
        if self.central_nms_login():
            log.info("Central NMS UI login successful.")
        else:
            log.err("Central login failed. Abort.")
            sys.exit(-1)

    def getPortalHost(self):
        return portalDomainList[self.instname]

    def getPortalUrl(self, path=""):
        return "https://" + portalDomainList[self.instname] + path

    def getUiUrl(self, path=""):
        return "https://" + uiDomainList[self.instname] + path

    def getApigwUrl(self, path=""):
        return "https://" + apigwDomainList[self.instname] + path

    def _apises_update(self):
        self.apiSes.headers.update({"Authorization": f"Bearer {self.accToken}"})


    ########################
    #   API I/F
    ########################
    def apiReq(self, method, endpoint, *args, **kwargs):
        if self.accToken == '':
            if not self._get_api_token():
                return False
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        url = "https://" + apigwDomainList[self.instname] + endpoint
        return self._request_ses(self.apiSes, method, url, *args, **kwargs)

    def apiGet(self, endpoint, *args, **kwargs):
        if self.accToken == '':
            if not self._get_api_token():
                return False
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        url = "https://" + apigwDomainList[self.instname] + endpoint
        return self._request_ses(self.apiSes, "GET", url, *args, **kwargs)

    def apiPost(self, endpoint, *args, **kwargs):
        if self.accToken == '':
            if not self._get_api_token():
                return False
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        url = "https://" + apigwDomainList[self.instname] + endpoint
        return self._request_ses(self.apiSes, "POST", url, *args, **kwargs)

    def nmsGet(self, endpoint, *args, **kwargs):
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        url = "https://" + uiDomainList[self.instname] + endpoint
        return self._request_ses(self.uiSes, "GET", url, *args, **kwargs)

    def nmsPost(self, endpoint, *args, **kwargs):
        if not endpoint.startswith("/"):
            endpoint = "/" + endpoint
        url = "https://" + uiDomainList[self.instname] + endpoint
        return self._request_ses(self.uiSes, "POST", url, *args, **kwargs)

    #
    #   request wrapper
    #
    def _get_request(self, url, *args, **kwargs):
        return self._request_ses(self.uiSes, "GET", url, *args, **kwargs)

    def _post_request(self, url, *args, **kwargs):
        return self._request_ses(self.uiSes, "POST", url, *args, **kwargs)

    def _request_ses(self, ses, method, url, *args, **kwargs):
        log.debug(f"\t{method} {url}")
        try:
            resp = ses.request(method=method, url=url, *args, **kwargs)
        except requests.exceptions.ConnectionError as e:
            log.err(f"HTTP connection error - {str(root_cause(e))}")
            exit()
        except Exception as e:
            traceback.print_exc()
            log.err(f"got error:{str(e)} abort.")
            exit()

        log.debug(f"\tStatus: {resp.status_code} {resp.reason} ({len(resp.content)} bytes)")
        if resp.status_code != 200:
            log.debug(f"response='{resp.content}'")
        return resp

    ################################################################
    #   pycentral I/F
    ################################################################
    def command(self, apiMethod, apiPath, apiData={}, apiParams={},
                headers={}, files={}, retry_api_call=True):
        if self.accToken == '':
            if not self._get_api_token():
                return False
        retry = 0
        result = ''
        while retry <= 1:
            if not retry_api_call:
                retry = 100
            if not headers and not files:
                headers = {
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
            if apiData and headers['Content-Type'] == "application/json":
                apiData = json.dumps(apiData)

            resp = self.apiReq(apiMethod, apiPath, data=apiData,
                                   headers=headers, params=apiParams, files=files)

            if resp.status_code == 401 and "invalid_token" in resp.text and retry_api_call:
                log.warn("Received error 401 on requesting url "
                                  "%s with resp %s" % (str(url), str(resp.text)))
                if retry < 1:
                    self._refresh_token()
                retry += 1
            else:
                result = {
                    "code": resp.status_code,
                    "msg": resp.text,
                    "headers": dict(resp.headers)
                }
                try:
                    result["msg"] = json.loads(result["msg"])
                except:
                    pass
                return result

        return False    # retry over

    ###############################################################
    #
    #   HPE SSO
    #
    ###############################################################
    def hpe_sso(self):

        if self.username == '':
            log.err("hpe_sso: username is empty.")
            return False
        if self.password == '':
            log.err("hpe_sso: password is empty.")
            return False

    ###############################################################
    #   HPESSO Pass 1
    ###############################################################
        print("[HPESSO] Pass 1 - Initiate HPE SSO")
        tgt_central = self.getPortalUrl("/platform/login/user")
        tgt_res = "https://sso.arubanetworks.com/idp/startSSO.ping?PartnerSpId=PRD:Athena:SP&TargetResource=" + \
                  urllib.parse.quote(tgt_central, safe='')
        url = "https://sso.arubanetworks.com/sp/startSSO.ping?PartnerIdpId=login.ext.hpe.com&TargetResource=" + \
              urllib.parse.quote(tgt_res, safe='')

        resp1 = self._get_request(url)

        soup = BeautifulSoup(resp1.content, features="html.parser")
        try:
            saml_code = soup.find('input', {'name': 'SAMLRequest'}).get('value')
            relaystate = soup.find('input', {'name': 'RelayState'}).get('value')
            url = soup.find('form').get('action')
            log.debug(f"\tGot Action URL={url}")
        except:
            log.err(f"Invalid SAML message.")
            return False

    ###############################################################
    #   HPESSO Pass 2
    ###############################################################
        print("[HPESSO] Pass 2 - POST SAML Request 1/2")
        resp2 = self._post_request(
            url=url,
            data={
                "SAMLRequest": saml_code,
                "RelayState": relaystate,
            }
        )

        soup = BeautifulSoup(resp2.content, features="html.parser")
        try:
            saml_code = soup.find('input', {'name': 'SAMLRequest'}).get('value')
            relaystate = soup.find('input', {'name': 'RelayState'}).get('value')
            url = soup.find('form').get('action')
            log.debug(f"\tGot Action URL={url}")
        except:
            log.err(f"Invalid SAML message.")
            return False

    ###############################################################
    #   HPESSO Pass 3
    ###############################################################
        print("[HPESSO] Pass 3 - POST SAML Request 2/2")
        resp3 = self._post_request(
            url=url,
            data={
                "SAMLRequest": saml_code,
                "RelayState": relaystate,
            }
        )

        soup = BeautifulSoup(resp3.content, features="html.parser")
        try:
            url = soup.find('form').get('action')
            log.debug(f"\tGot Action URL={url}")
        except:
            log.err(f"Invalid SAML message.")
            return False

        if not url.startswith("http"):
            url = "https://" + urllib.parse.urlparse(resp3.url).netloc + url

    ###############################################################
    #   HPESSO Pass 4
    ###############################################################
        print("[HPESSO] Pass 4 - Post Credential")
        resp4 = self._post_request(
            url=url,
            data={
                "pf.username": self.username,
                "pf.pass": self.password,
            }
        )
        soup = BeautifulSoup(resp4.content, features="html.parser")
        try:
            saml_code = soup.find('input', {'name': 'SAMLResponse'}).get('value')
            relaystate = soup.find('input', {'name': 'RelayState'}).get('value')
            url = soup.find('form').get('action')
            log.debug(f"\tGot SAML response... {saml_code[0:20]}...(snip)...{saml_code[-20:-1]}")
        except:
            log.err("SAML Response is invalid.")
            return False

    ###############################################################
    #   HPESSO Pass 5
    ###############################################################
        print("[HPESSO] Pass 5 - Post SAML Response 1/3")
        resp5 = self._post_request(
            url=url,
            data={
                "SAMLResponse": saml_code,
                "RelayState": relaystate,
            }
        )
        soup = BeautifulSoup(resp5.content, features="html.parser")
        try:
            saml_code = soup.find('input', {'name': 'SAMLResponse'}).get('value')
            relaystate = soup.find('input', {'name': 'RelayState'}).get('value')
            url = soup.find('form').get('action')
            log.debug(f"\tGot SAML response... {saml_code[0:20]}...(snip)...{saml_code[-20:-1]}")
        except:
            log.err("SAML Response is invalid.")
            return False

    ###############################################################
    #   HPESSO Pass 6
    ###############################################################
        print("[HPESSO] Pass 6 - Post SAML Response 2/3")
        resp6 = self._post_request(
            url=url,
            data={
                "SAMLResponse": saml_code,
                "RelayState": relaystate,
            }
        )
        soup = BeautifulSoup(resp6.content, features="html.parser")
        try:
            saml_code = soup.find('input', {'name': 'SAMLResponse'}).get('value')
            relaystate = soup.find('input', {'name': 'RelayState'}).get('value')
            url = soup.find('form', {'method': 'post'}).get('action')
            log.debug(f"\tGot SAML response... {saml_code[0:20]}...(snip)...{saml_code[-20:-1]}")
        except:
            log.err("SAML Response is invalid.")
            return False

    ###############################################################
    #   HPESSO Pass 7
    ###############################################################
        print("[HPESSO] Pass 7 - Post SAML Response 3/3")
        resp7 = self._post_request(
            url=url,
            data={
                "SAMLResponse": saml_code,
                "RelayState": relaystate,
            }
        )
        soup = BeautifulSoup(resp7.content, features="html.parser")
        try:
            ref_code = soup.find('input', {'name': 'REF'}).get('value')
            log.debug(f"\tGot SAML REF Code... {ref_code}")
        except:
            log.err("SAML REF Code not found.")
            return False

        return ref_code


    ###############################################################
    #
    #   Aruba SSO
    #
    ###############################################################
    def aruba_sso(self):

        if self.username == '':
            log.err("aruba_sso: username is empty.")
            return False
        if self.password == '':
            log.err("aruba_sso: password is empty.")
            return False

    ###############################################################
    #   [SSO] Pass 1
    ###############################################################
        print("[SSO] Pass 1 - Initiate SSO redirect")
        url = self.getPortalUrl("/platform/login/aruba/sso")
        resp1 = self._post_request(
            url=url,
            params={
                "username": self.username,
            },
            data={
                "pf.username": self.username,
            },
        )

        log.debug(f"\tGot Idp URL... {resp1.url}")

    ###############################################################
    #   [SSO] Pass 2
    ###############################################################
        print("[SSO] Pass 2 - Post Credentials to Idp")
        url = resp1.url
        resp2 = self._post_request(
            url=url,
            data={
                "pf.username": self.username,
                "pf.pass": self.password,
            }
        )
        soup = BeautifulSoup(resp2.content, features="html.parser")
        try:
            saml_code = soup.find('input', {'name': 'SAMLResponse'}).get('value')
            relaystate = soup.find('input', {'name': 'RelayState'}).get('value')
            url = soup.find('form').get('action')
            log.debug(f"\tGot SAML response... {saml_code[0:20]}...(snip)...{saml_code[-20:-1]}")
        except:
            log.err("SAML Response is invalid.")
            return False

    ###############################################################
    #   [SSO] Pass 3
    ###############################################################
        print("[SSO] Pass 3 - Post SAML code to SSO ACS")
        resp3 = self._post_request(
            url=url,
            data={
                "RelayState": relaystate,
                "SAMLResponse": saml_code,
            }
        )
        soup = BeautifulSoup(resp3.content, features="html.parser")
        try:
            ref_code = soup.find('input', {'name': 'REF'}).get('value')
            log.debug(f"\tGot SAML REF Code... {ref_code}")
        except:
            log.err("SAML REF Code not found.")
            return False

        return ref_code


    ###############################################################
    #   Login to Central Frontend
    ###############################################################
    def central_nms_login(self):

        if self.username is None or self.username == '':
            log.err("Username is not specified.")
            return False

        if self.password is None or self.password == '':
            self.password = getpass.getpass("Password: ")

        if '@hpe.com' in self.username:
            ref_code = self.hpe_sso()
        else:
            ref_code = self.aruba_sso()

        if not ref_code:
            log.err("Login failed.")
            return False

    ###############################################################
    #   [Central] Pass 1
    ###############################################################
        print("[Central] Pass 1 - Post SAML REF to Aruba Central")
        url = self.getPortalUrl("/platform/login/user")
        resp1 = self._post_request(
            url=url,
            data={
                "REF": ref_code,
                "TargetResource": url,
            },
        )
        r = re.search("<title>([^<]+)</title>", resp1.text)
        if not r:
            log.err("Got unknown response.")
            log.debug(f"response='{resp1.text}'")
            return False

        t = r.group(1)
        if t == 'Logging out':
            log.err("Login failed.")
            return False
        elif t == "Select Account":
            pass
        elif t == "Aruba Central":
            log.debug("Single customer account")
        else:
            log.err(f"Got unknown title '{t}'")
            return False

    ###############################################################
    #   Customer selection
    ###############################################################
        if self.customerId is None or self.customerId == '':
            self.customerId = self._get_customerid()

    ###############################################################
    #   [Central] Pass 2
    ###############################################################
        print(f"[Central] Pass 2 - Select user account (CID: {self.customerId})")
        url = self.getPortalUrl("/platform/login/customers/selection")
        resp2 = self._post_request(
            url=url,
            headers={
                "Content-type": "application/json;charset=utf-8",
                "Host": self.getPortalHost()
            },
            json={
                "cid": self.customerId
            }
        )
        try:
            r = json.loads(resp2.text)["redirect_url"]
        except json.decoder.JSONDecodeError:
            log.err(f"Customer ID '{self.customerId}' is invalid.")
            return False

        log.debug(f"Got reirect_url: {r}")

    ###############################################################
    #   [Central] Pass 3
    ###############################################################
        print("[Central] Pass 3 - Launch NMS")
        url = self.getPortalUrl("/platform/login/apps/nms/launch")
        resp3 = self._get_request(url)

        self.nmsLogin = True
        return True


    ###############################################################
    #   OAuth Login to API
    ###############################################################
    def central_api_login(self):

        if self.username is None or self.username == '':
            log.err("Username is not specified.")
            return False

        if '@hpe.com' in self.username or '@arubanetworks.com' in self.username:
            print("username with domain @hpe.com or @arubanetworks.com is not supported.")
            return False

        if self.password is None or self.password == '':
            self.password = getpass.getpass("Password: ")

        if self.clientId == '' or self.clientSecret == '':
            if not self.nmsLogin:
                self.central_nms_login()
            self._get_client_creds()

    ###############################################################
    #   [API] Pass 1 - Login
    ###############################################################
        print("[API] Pass 1 - Login")
        resp1 = self.apiPost(
            endpoint = "/oauth2/authorize/central/api/login",
            params = { "client_id": self.clientId },
            headers={
                'Content-Type': 'application/json',
            },
            json={
                "username": self.username,
                "password": self.password,
            },
        )

        if resp1.status_code != 200:
            log.err(f"Got error {resp1.status_code}. abort.")
            return False

        log.debug(f"Get Response: {resp1.content}")

    ###############################################################
    #   [API] Pass 2 - Generate Authorization Code
    ###############################################################
        print("[API] Pass 2 - Get Authorization code")
        resp2 = self.apiPost(
            endpoint = "/oauth2/authorize/central/api",
            params = {
                "client_id": self.clientId,
                "response_type": "code",
                "scope": "all",
            },
            headers={
                'Content-Type': 'application/json',
                #'X-CSRF-Token': 'xxxx',
            },
            json={
                'customer_id': self.customerId
            }
        )

        if resp2.status_code != 200:
            log.err(f"Got error {resp2.status_code}. abort.")
            return False

        log.debug(f"Get Response: {resp2.content}")
        auth_code = json.loads(resp2.content)["auth_code"]
        log.debug(f"API auth successful. Auth code={auth_code}")

    ###############################################################
    #   [API] Pass 3 - Get Token
    ###############################################################
        print("[API] Pass 3 - Get Access token")
        resp3 = self.apiPost(
            endpoint = "/oauth2/token",
            params = {
                "client_id": self.clientId,
                "client_secret": self.clientSecret,
                "grant_type": "authorization_code",
                "code": auth_code,
            },
            headers={
                'Content-Type': 'application/json',
                #'X-CSRF-Token': 'xxxx',
            },
        )

        if resp3.status_code != 200:
            log.err(f"Got error {resp3.status_code}. abort.")
            return False

        log.debug(f"Get Response: {resp3.content}")
        j = json.loads(resp3.content)
        self.accToken = j['access_token']
        self.refToken = j['refresh_token']
        self._apises_update()
        log.debug(f"Got Tokens. acc={self.accToken}, ref={self.refToken}")

        return True


    ################################################################
    #   Generate New Access Token via Central UI
    ################################################################
    def _generate_acc_token(self):
        log.debug("generate_acc_token: Generating new token...")
        url = self.getPortalUrl("/user_apigw/apps/nms/oauth/credentials")
        csrftoken = self.uiSes.cookies.get("csrftoken", domain=self.getPortalHost())
        resp = self._post_request(
            url=url,
            json={
                "client_display_name": self.appName,
                "self.appName": "nms",
                "redirect_uri": "",
            },
            headers={
                "referer": self.getPortalUrl("/platform/frontend/"),  # Mandatory
                "x-requested-with": "XMLHttpRequest",   # Mandatory
                "x-csrf-token": csrftoken   # Mandatory
            }
        )

        if resp.status_code != 200:
            log.err(f"generate_acc_token: Got error {resp.status_code}.")
            return False

        log.debug(f"generate_acc_token: Get Response: {resp.content}")
        j = json.loads(resp.content)
        self.accToken = j['access_token']
        self.refToken = j['refresh_token']
        self._apises_update()
        self._save_tokens()

        log.info(f"generate_acc_token: Tokens generated for app '{self.appName}', AccToken='{self.accToken}', RefToken='{self.refToken}'")
        return True


    ################################################################
    #   Refresh access token
    ################################################################
    def _refresh_token(self):
        assert(self.appName != "")
        if self.clientId == '' or self.clientSecret == '':
            if not self._get_client_creds():      # get self.clientId and self.clientSecret
                log.info(f"refresh_token: appname '{self.appName}' not found in UI. adding it...")
                if not self._generate_acc_token():
                    log.err(f"Token generation failed. Abort.")
                    sys.exit(-1)
                # token newly generated, no need to refresh
                sleep(1)
                return True

        resp = self.apiPost(
            endpoint = "/oauth2/token",
            params = {
                "client_id": self.clientId,
                "client_secret": self.clientSecret,
                "grant_type": "refresh_token",
                "refresh_token": self.refToken,
            }
        )
        if resp.status_code != 200:
            log.debug(f"refresh_token: Refresh failed. body='{resp.content}'")
            return False

        log.debug(f"refresh_token: Refresh successful! body='{resp.content}'")
        j = json.loads(resp.content)
        self.accToken = j['access_token']
        self.refToken = j['refresh_token']
        self._apises_update()
        self._save_tokens()

        log.info(f"refresh_token: Token refreshed. AccToken={self.accToken}, RefToken={self.refToken}")
        return True

    ################################################################
    #   Check if Acccess Token is valid
    #   If it's not, try to refresh it
    #   If it fails, try to generate new one
    ################################################################
    def _check_and_refresh(self):
        resp = self.apiGet(
            endpoint = "/configuration/v2/groups",
            params = {
                "limit": 10,
                "offset": 0,
            })
        if resp.status_code == 200:
            log.debug("check_and_refresh: Access Token is valid.")
            return True

        log.debug(f"check_and_refresh: got response {resp.status_code}")

        if resp.status_code != 401:
            return False            # unknown error response

        j = json.loads(resp.content)
        if j['error'] == 'invalid_token':
            log.debug("check_and_refresh: Got invalid_token error. refreshing tokens...")
            if self._refresh_token():
                log.debug("check_and_refresh: token refresh successful. retrying API access ...")
                resp2 = self.apiGet(
                    endpoint="/configuration/v2/groups",
                    params={
                        "limit": 10,
                        "offset": 0,
                    })
                if resp2.status_code == 200:
                    log.debug("check_and_refresh: API Token is valid.")
                    return True
                else:
                    log.debug(f"check_and_refresh: API access failed. response='{resp2.content}'")
                    return False
            else:   # token refresh failed
                return self._generate_acc_token()

        log.err(f"check_and_refresh: Got error: {j['error']}")
        return False

    ################################################################
    #   get valid Access Token
    ################################################################
    def _get_api_token(self):
        if not self._restore_tokens():
            print("Cached token not found. retrieveing new token...")
            if self.appName is None or self.appName == '':
                if not self._get_client_creds():  # select appName from application list in Central UI
                    self.appName = input("Enter App name: ")
            if not self._generate_acc_token():
                return False

        return self._check_and_refresh()

    ########################
    #   Token storage
    ########################
    def _restore_tokens(self):
        """
        Search an entry from token cache file with matching username, customerId and appName
        If appName is not specified, search an entry with matching username and customerId
        The search starts from the last line (=latest updated entry) toward the first line
        Returns True if matching entry is found. False if none matched.
        Updates Authorization header in apiSes
        :return:
            True    match and updated accToken/refToken
            False   no match
        """

        try:
            with open(self.tokenCacheFile, mode="r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            log.info(f"restore_tokens: Token cache file {self.tokenCacheFile} not found.")
            return False

        for l in reversed(lines):       # search from last one to first one
            d = l.rstrip().split(',')
            if len(d) < 5:
                continue

            if self.appName is None or self.appName == '':
                if d[0] == self.username and d[1] == self.customerId:
                    self.appName  = d[2]
                    self.accToken = d[3]
                    self.refToken = d[4]
                    self._apises_update()
                    log.debug(f"restore_tokens: Found matching tokens in cache for app '{self.appName}', AccToken='{self.accToken}', RefToken='{self.refToken}'")
                    return True
            else:
                if d[0] == self.username and d[1] == self.customerId and d[2] == self.appName:
                    self.accToken = d[3]
                    self.refToken = d[4]
                    self._apises_update()
                    log.debug(f"restore_tokens: Found matching tokens in cache for app '{self.appName}', AccToken='{self.accToken}', RefToken='{self.refToken}'")
                    return True

        log.debug("restore_token: No matching token found in cache")
        return False

    def _save_tokens(self):
        """
        Search an entry in token cache file by username, customerId, appName and
        update the matching entry in with current accToken/refToken information
        Create a file if the cache file does not exist
        """
        try:
            with open(self.tokenCacheFile, mode="r") as f:
                lines = f.readlines()
        except FileNotFoundError:
            log.info(f"save_tokens: Token cache file {self.tokenCacheFile} not found. creating new file.")
            lines = []

        cont = []
        for l in lines:
            d = l.rstrip().split(',')
            if len(d) < 5:
                continue
            if d[0] == self.username and d[1] == self.customerId and d[2] == self.appName:
                continue
            cont.append(l)

        cont.append(f"{self.username},{self.customerId},{self.appName},{self.accToken},{self.refToken}\n")
        with open(self.tokenCacheFile, mode="w") as f:
            f.write("".join(cont))
        log.debug(f"save_tokens: Token cache updated.")

        return True

    ########################
    #   Select customer
    ########################
    def _get_customerid(self):
        '''
        Print list of customers and let user select one
        '''

        url = self.getPortalUrl("/platform/login/customers")
        resp = self._get_request(url)
        j = json.loads(resp.content)
        clist = j['customers_list']
        assert(len(clist)>=1)
        table = []
        for c in clist:
            name, email, cid, ctime = get_mkeys(c, 'name', 'email', 'id', 'created_at')
            created = datetime.fromtimestamp(ctime).strftime("%Y-%m-%d")
            table.append([name, email, cid, created])
        df = pd.DataFrame(data=table, columns=['Name', 'Email', 'CID', 'Created'])
        df.index = df.index + 1

        assert(len(df)>=1)
        print("--- Customer List ---")
        print(df)

        max = len(clist)
        while True:
            if max == 1:
                i = 1
                break
            i = input(f"Select customer[1-{max}]: ")
            i = int(i)
            if 1<=i and i<=max:
                break
        log.info(f"Selected {df.loc[i, 'Name']} (CID:{df.loc[i, 'CID']})")
        return df.loc[i, 'CID']


    ###############################################################
    #   Get clientID/clientSecret from the client list in Central UI
    #   if appName is empty, let user select one
    #   if appName is not empty, search the matching name from the list
    ###############################################################
    def _get_client_creds(self):
        """
        API client ID/secret ?????????
        :return:
        """
        url = self.getPortalUrl("/user_apigw/oauth/credentials?all_apps=true")
        resp = self._get_request(url)
        j = json.loads(resp.content)['data']

        if self.appName is None or self.appName == '':
            table = []
            for a in j:
                name, cliid, clisec, ctime, redir = get_mkeys(a, 'name', 'client_id', 'client_secret', 'created_at', 'redirect_uri')
                created = datetime.fromtimestamp(ctime/1000).strftime("%Y-%m-%d")
                table.append([name, cliid, clisec, created, redir[0]])
            df = pd.DataFrame(data=table, columns=['Name', 'Client ID', 'Client Secret', 'Created', 'Redirect URI'])
            df.index = df.index + 1

            if len(df) == 0:
                print("No API Client found.")
                return False

            print("--- API Client List ---")
            print(df)

            max = len(j)
            while True:
                if max == 1:
                    i = 1
                    break
                i = input(f"Select API Client[1-{max}]: ")
                i = int(i)
                if 1 <= i and i <= max:
                    break
            self.appName = df.loc[i, 'Name']
            self.clientId = df.loc[i, 'Client ID']
            self.clientSecret = df.loc[i, 'Client Secret']
            log.info(f"Selected {self.appName} (CID:{self.clientId})")
            return True

        #
        #   search appName from list
        #
        for d in j:
            if d['name'] != self.appName:
                continue
            log.debug(f"get_client_creds: cliendId/clientSecret found for application {self.appName}")
            self.clientId = d['client_id']
            self.clientSecret = d['client_secret']
            return True

        log.info(f"get_client_creds: Client credentials not found for application {self.appName}")
        return False

#
#   end of CentralSession class
#

def _import_config(names):
    cfg = importlib.import_module("central_config")
    for n in names:
        try:
            v = getattr(cfg, n)
            globals().update({n: v})
        except AttributeError:
            globals().update({n: ""})

def create_session_from_config():
    _import_config(['username', 'password', 'instance', 'customer_id', 'app_name'])
    return CentralSession(instance, username, password, customer_id, app_name)

################################################################
#   main
################################################################
if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description="login to central NMS and create API token")
    parser.add_argument('--debug', help='Enable debug log', action='store_true')
    parser.add_argument('--info', help='Enable informational log', action='store_true')
    args = parser.parse_args()

    if args.debug:
        log.setloglevel(log.LOG_DEBUG)
    elif args.info:
        log.setloglevel(log.LOG_INFO)
    else:
        log.setloglevel(log.LOG_WARN)

    central = create_session_from_config()

    #   Test API
    print("\nTesting API...")
    resp = central.apiGet(
        endpoint="/configuration/v2/groups",
        params={
            "limit": 20,
            "offset": 0
        })
    print(resp.text)

    #   Test API (pycentral I/F)
    print("\nTesting API...")
    resp = central.command(
        apiMethod="GET",
        apiPath="/configuration/v2/groups",
        apiParams={
            "limit": 20,
            "offset": 0
        })
    print(resp)

    sys.exit(0)
