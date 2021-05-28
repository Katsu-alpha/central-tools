#!/usr/bin/python3
#
#    ToDo:
#       encrypt disable config を取得する方法
#       session の永続化
#       inventory のクラス化
#       コメント英語化
#       ログファイルの書き出し
#       エラーチェック、assert
#

import sys
import argparse
import json
import urllib
import urllib.parse as urlparse
from datetime import datetime
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


def sethdr(args, hdr, cont):
    if 'headers' in args:
        args['headers'][hdr] = cont
    else:
        args['headers'] = {hdr: cont}


########################
#   Main class
########################
class CentralSession:
    """
    Central との http セッションを管理する。
    UI/API へのログイン、GET/POST インタフェース、Access Token 保存・更新
    """
    def __init__(self, username="", password="", instname="internal", customerid='', appname=''):
        self.uiSes = requests.Session()         # session for Central NMS App
        self.apiSes = requests.Session()        # session for Central API
        self.accToken = ""
        self.refToken = ""
        self.username = username
        self.password = password
        self.instname = instname
        self.customerId = customerid
        self.appName = appname
        self.clientId = ""
        self.clientSecret = ""
        self.nmsLogin = False
        self.apiLogin = False
        self.tokenCacheFile = 'tokens.txt'


    def getPortalHost(self):
        return portalDomainList[self.instname]

    def getPortalUrl(self, path=""):
        return "https://" + portalDomainList[self.instname] + path

    def getUiUrl(self, path=""):
        return "https://" + uiDomainList[self.instname] + path

    def getApigwUrl(self, path=""):
        return "https://" + apigwDomainList[self.instname] + path

    def apises_update(self):
        self.apiSes.headers.update({"Authorization": f"Bearer {self.accToken}"})


    ########################
    #   HTTP I/F
    ########################
    def get_request(self, url, *args, **kwargs):
        return self.get_request_ses(self.uiSes, url, *args, **kwargs)

    def post_request(self, url, *args, **kwargs):
        return self.post_request_ses(self.uiSes, url, *args, **kwargs)

    def get_request_api(self, url, *args, **kwargs):
        return self.get_request_ses(self.apiSes, url, *args, **kwargs)

    def post_request_api(self, url, *args, **kwargs):
        return self.post_request_ses(self.apiSes, url, *args, **kwargs)

    #
    #   get/post wrapper
    #
    def get_request_ses(self, ses, url, *args, **kwargs):
        log.debug(f"\tGET {url}")
        try:
            resp = ses.get(url=url, *args, **kwargs)
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


    def post_request_ses(self, ses, url, *args, **kwargs):
        log.debug(f"\tPOST {url}")
        try:
            resp = ses.post(url=url, *args, **kwargs)
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


    ########################
    #   Token storage
    ########################
    def restore_tokens(self):
        """
        token.txt から username, customerId, appName がマッチする行を検索し、accToken, refToken を読み込む。
        ただし appName が指定されていない場合、username, customerId がマッチする最新のエントリから appName を取得する。
        マッチした行があれば True を、見つからなければ False を返す。
        apiSes の Authorization ヘッダを accToken でアップデートする
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
                    self.apises_update()
                    log.debug(f"restore_tokens: Found matching tokens in cache for app '{self.appName}', AccToken='{self.accToken}', RefToken='{self.refToken}'")
                    return True
            else:
                if d[0] == self.username and d[1] == self.customerId and d[2] == self.appName:
                    self.accToken = d[3]
                    self.refToken = d[4]
                    self.apises_update()
                    log.debug(f"restore_tokens: Found matching tokens in cache for app '{self.appName}', AccToken='{self.accToken}', RefToken='{self.refToken}'")
                    return True

        log.debug("restore_token: No matching token found in cache")
        return False

    def save_tokens(self):
        """
        tokens.txt を username, customerId, appName で検索し、現在の accToken, refToken に書き換える。
        ファイルがない場合は新規作成。
        :return: 
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
    def get_customerid(self):
        '''
        Print list of customers and let user select one
        '''

        url = self.getPortalUrl("/platform/login/customers")
        resp = self.get_request(url)
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
    def get_client_creds(self):
        """
        API client ID/secret を取得
        :return: 
        """
        url = self.getPortalUrl("/user_apigw/oauth/credentials?all_apps=true")
        resp = self.get_request(url)
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


    ###############################################################
    #   HPE SSO
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

        resp1 = self.get_request(url)

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
        resp2 = self.post_request(
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
        resp3 = self.post_request(
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
        resp4 = self.post_request(
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
            log.debug(f"\tGot SAML response... {saml_code[0:40]}...(snip)...{saml_code[-40:-1]}")
        except:
            log.err("SAML Response is invalid.")
            return False

    ###############################################################
    #   HPESSO Pass 5
    ###############################################################
        print("[HPESSO] Pass 5 - Post SAML Response 1/3")
        resp5 = self.post_request(
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
            log.debug(f"\tGot SAML response... {saml_code[0:40]}...(snip)...{saml_code[-40:-1]}")
        except:
            log.err("SAML Response is invalid.")
            return False

    ###############################################################
    #   HPESSO Pass 6
    ###############################################################
        print("[HPESSO] Pass 6 - Post SAML Response 2/3")
        resp6 = self.post_request(
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
            log.debug(f"\tGot SAML response... {saml_code[0:40]}...(snip)...{saml_code[-40:-1]}")
        except:
            log.err("SAML Response is invalid.")
            return False

    ###############################################################
    #   HPESSO Pass 7
    ###############################################################
        print("[HPESSO] Pass 7 - Post SAML Response 3/3")
        resp7 = self.post_request(
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


    def aruba_sso(self):

        if self.username == '':
            log.err("aruba_sso: Please specify username.")
            return False
        if self.password == '':
            log.err("aruba_sso: Please specify password.")
            return False

    ###############################################################
    #   [SSO] Pass 1
    ###############################################################
        print("[SSO] Pass 1 - Initiate SSO redirect")
        url = self.getPortalUrl("/platform/login/aruba/sso")
        resp1 = self.post_request(
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
        resp2 = self.post_request(
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
            log.debug(f"\tGot SAML response... {saml_code[0:40]}...(snip)...{saml_code[-40:-1]}")
        except:
            log.err("SAML Response is invalid.")
            return False

    ###############################################################
    #   [SSO] Pass 3
    ###############################################################
        print("[SSO] Pass 3 - Post SAML code to SSO ACS")
        resp3 = self.post_request(
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
        resp1 = self.post_request(
            url=url,
            data={
                "REF": ref_code,
                "TargetResource": url,
            },
        )

    ###############################################################
    #   Customer selection
    ###############################################################
        if self.customerId is None or self.customerId == '':
            self.customerId = self.get_customerid()

    ###############################################################
    #   [Central] Pass 2
    ###############################################################
        print(f"[Central] Pass 2 - Select user account (CID: {self.customerId})")
        url = self.getPortalUrl("/platform/login/customers/selection")
        resp2 = self.post_request(
            url=url,
            headers={
                "Content-type": "application/json;charset=utf-8",
                "Host": self.getPortalHost()
            },
            json={
                "cid": self.customerId
            }
        )

    ###############################################################
    #   [Central] Pass 3
    ###############################################################
        print("[Central] Pass 3 - Launch NMS")
        url = self.getPortalUrl("/platform/login/apps/nms/launch")
        resp3 = self. get_request(url)

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
            self.get_client_creds()

    ###############################################################
    #   [API] Pass 1 - Login
    ###############################################################
        print("[API] Pass 1 - Login")
        url = self.getApigwUrl(f"/oauth2/authorize/central/api/login?client_id={self.clientId}")
        resp1 = self.post_request_api(
            url=url,
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
        url = self.getApigwUrl(f"/oauth2/authorize/central/api?client_id={self.clientId}&response_type=code&scope=all")
        resp2 = self.post_request_api(
            url=url,
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
        url = self.getApigwUrl(f"/oauth2/token?client_id={self.clientId}&client_secret={self.clientSecret}&grant_type=authorization_code&code={auth_code}")
        resp3 = self.post_request_api(
            url=url,
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
        self.apises_update()
        log.debug(f"Got Tokens. acc={self.accToken}, ref={self.refToken}")

        return True


    ################################################################
    #   Generate New Access Token via Central UI
    ################################################################
    def generate_acc_token(self):
        log.debug("generate_acc_token: Generating new token...")
        url = self.getPortalUrl("/user_apigw/apps/nms/oauth/credentials")
        csrftoken = self.uiSes.cookies.get("csrftoken", domain=self.getPortalHost())
        resp = self.post_request(
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
            log.err(f"Got error {resp.status_code}.")
            return False

        log.debug(f"Get Response: {resp.content}")
        j = json.loads(resp.content)
        self.accToken = j['access_token']
        self.refToken = j['refresh_token']
        self.apises_update()
        log.info(f"generate_acc_token: Tokens generated for app '{self.appName}', AccToken='{self.accToken}', RefToken='{self.refToken}'")
        self.save_tokens()
        return True


    ################################################################
    #   Refresh access token
    ################################################################
    def refresh_token(self):
        assert(self.appName != "")
        if self.clientId == '' or self.clientSecret == '':
            if not self.get_client_creds():      # get self.clientId and self.clientSecret
                log.err("refresh_token: error retrieving client info. abort.")
                sys.exit(-1)

        url = self.getApigwUrl(f"/oauth2/token?client_id={self.clientId}&client_secret={self.clientSecret}&grant_type=refresh_token&refresh_token={self.refToken}")
        resp = self.post_request(url)
        if resp.status_code != 200:
            log.debug(f"refresh_token: Refresh failed. body='{resp.content}'")
            return False

        log.debug(f"refresh_token: Refresh successful! body='{resp.content}'")
        j = json.loads(resp.content)
        self.accToken = j['access_token']
        self.refToken = j['refresh_token']
        self.apises_update()
        log.info(f"refresh_token: Token refreshed. AccToken={self.accToken}, RefToken={self.refToken}")
        self.save_tokens()
        return True

    ################################################################
    #   Check if Acccess Token is valid
    #   If it's not, try to refresh it
    #   If it fails, try to generate new one
    ################################################################
    def check_and_refresh(self):
        url = self.getApigwUrl("/configuration/v2/groups?limit=10&offset=0")
        resp = self.get_request_api(url)
        if resp.status_code == 200:
            log.debug("check_and_refresh: Access Token is valid.")
            return True

        log.debug(f"check_and_refresh: got response {resp.status_code}")

        if resp.status_code != 401:
            return False            # unknown error response

        j = json.loads(resp.content)
        if j['error'] == 'invalid_token':
            log.debug("check_and_refresh: Got invalid_token error. refreshing tokens...")
            if self.refresh_token():
                log.debug("check_and_refresh: token refresh successful. retrying API access ...")
                resp2 = self.get_request_api(url)
                if resp2.status_code == 200:
                    log.debug("check_and_refresh: API Token is valid.")
                    return True
                else:
                    log.debug(f"check_and_refresh: API access failed. response='{resp2.content}'")
                    return False
            else:   # token refresh failed
                return self.generate_acc_token()

        return False

    #
    #   get valid Access Token
    #   called from other modules
    #
    def get_api_token(self):
        if not self.restore_tokens():
            print("Cached token not found. retrieveing new token...")
            if self.appName is None or self.appName == '':
                if not self.get_client_creds():  # select appName from application list in Central UI
                    self.appName = input("Enter App name: ")
            if not self.generate_acc_token():
                return False

        return self.check_and_refresh()

#
#   end of CentralSession class
#



def import_config(names):
    cfg = importlib.import_module("central_config")
    for n in names:
        try:
            v = getattr(cfg, n)
            globals().update({n: v})
        except AttributeError:
            globals().update({n: ""})

def create_session():
    import_config(['username', 'password', 'instance', 'customer_id', 'app_name'])
    return CentralSession(username, password, instance, customer_id, app_name)

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

    ses = create_session()

    if ses.central_nms_login():
        print("Central NMS UI login successful.")
    else:
        print("Login failed.")
        sys.exit(-1)

    #if ses.central_api_login():
    #    print("Central API login successful.")

    if ses.get_api_token():
        print("Get API token successful.")
    else:
        log.err("Failed to get API token.")
        sys.exit(-1)

    sys.exit(0)
