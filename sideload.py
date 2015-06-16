#!/usr/bin/python
# -*- coding: utf-8 -*-

# created by Kevin Ko (@uhelios)

import urllib
import httplib
import sys
import re
import os.path
import shutil
import time
import zipfile
import json
import uuid
import urlparse
import StringIO
import gzip
import logging
import base64
import mechanize
import argparse
import plistlib
import uuid
import cookielib
import certificate
import base64

from datetime import date
from coda_network import urllib2
from bs4 import BeautifulSoup
from os.path import basename
from urlparse import urlsplit
from cookielib import CookieJar
from types import *

def isValidUDID(udid):
    if len(udid) == 40:
        if udid[:8] != "FFFFFFFF":
            if udid.islower() == True:
                return True
    return False

class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        result = urllib2.HTTPRedirectHandler.http_error_302(self, req, fp,
                                                                 code, msg,
                                                                 headers)
        result.code = code
        result.headers = headers
        return result

class sideload:
    def __init__(self, account_username, account_password, udid, app_id):
        self.account_username = account_username
        self.account_password = account_password

        if isValidUDID(udid):
            self.udid = udid
        else:
            logger.error("Invalid UDID entry.")
            sys.exit(0)

        self.app_id = app_id
        self.clientId = "XABBG36SBB"
        self.appIdKey = "ba2ec180e6ca6e6c6a542255453b24d6e6e5b2be0cc48bc1b0d8ad64cfe0228f"
        self.accountBlob = ""
        self.teamId = ""

        self.browser = mechanize.Browser()
        self.cookiejar = CookieJar()
        self.browser.set_cookiejar(self.cookiejar)
        self.browser.set_handle_equiv(True)
        self.browser.set_handle_gzip(True)
        self.browser.set_handle_redirect(True)
        self.browser.set_handle_referer(True)
        self.browser.set_handle_robots(False)
        self.browser.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)
        self.browser.addheaders = [('User-Agent', "Xcode"), ('Accept', 'text/x-xml-plist'), ('X-Xcode-Version', '7.0 (7A120f)')]
    
    def downloadProvisioningProfile(self, appIdId):
        requestId = str(uuid.uuid4()).upper()
        postData = {"clientId": self.clientId,
                    "myacinfo": self.accountBlob,
                    "protocolVersion": "QH65B2",
                    "requestId": requestId,
                    "teamId": self.teamId,
                    "appIdId": appIdId,
                    "userLocale": ["en_US"]}
        plist = plistlib.writePlistToString(postData)
        response = self.browser.open(urllib2.Request("https://developerservices2.apple.com/services/QH65B2/ios/downloadTeamProvisioningProfile.action?clientId=" + self.clientId, plist, {'Content-Type': 'text/x-xml-plist'}))
        responseData = response.read()
        root = plistlib.readPlistFromString(responseData)
        return root["provisioningProfile"]

    def removeAppId(self, appIdId):
        requestId = str(uuid.uuid4()).upper()
        postData = {"clientId": self.clientId,
                    "myacinfo": self.accountBlob,
                    "protocolVersion": "QH65B2",
                    "requestId": requestId,
                    "teamId": self.teamId,
                    "appIdId": appIdId,
                    "userLocale": ["en_US"]}
        plist = plistlib.writePlistToString(postData)
        response = self.browser.open(urllib2.Request("https://developerservices2.apple.com/services/QH65B2/ios/deleteAppId.action?clientId=" + self.clientId, plist, {'Content-Type': 'text/x-xml-plist'}))
        responseData = response.read()
        return responseData

    def addAppId(self, identifier):
        requestId = str(uuid.uuid4()).upper()
        postData = {"clientId": self.clientId,
                    "myacinfo": self.accountBlob,
                    "protocolVersion": "QH65B2",
                    "requestId": requestId,
                    "teamId": self.teamId,
                    "entitlements": [],
                    "identifier": identifier,
                    "name": "Xcode iOS App ID " + identifier.replace(".", " "),
                    "appIdName": "Xcode iOS App ID " + identifier.replace(".", " "),
                    "userLocale": ["en_US"]}
        plist = plistlib.writePlistToString(postData)
        response = self.browser.open(urllib2.Request("https://developerservices2.apple.com/services/QH65B2/ios/addAppId.action?clientId=" + self.clientId, plist, {'Content-Type': 'text/x-xml-plist'}))
        responseData = response.read()
        root = plistlib.readPlistFromString(responseData)
        return root

    def listAppIds(self):
        requestId = str(uuid.uuid4()).upper()
        postData = {"clientId": self.clientId,
                    "myacinfo": self.accountBlob,
                    "protocolVersion": "QH65B2",
                    "requestId": requestId,
                    "teamId": self.teamId,
                    "userLocale": ["en_US"]}
        plist = plistlib.writePlistToString(postData)
        response = self.browser.open(urllib2.Request("https://developerservices2.apple.com/services/QH65B2/ios/listAppIds.action?clientId=" + self.clientId, plist, {'Content-Type': 'text/x-xml-plist'}))
        responseData = response.read()
        root = plistlib.readPlistFromString(responseData)
        return root["appIds"]

    def downloadDevelopmentCert(self):
        requestId = str(uuid.uuid4()).upper()
        postData = {"clientId": self.clientId,
                    "myacinfo": self.accountBlob,
                    "protocolVersion": "QH65B2",
                    "requestId": requestId,
                    "teamId": self.teamId,
                    "userLocale": ["en_US"]}
        plist = plistlib.writePlistToString(postData)
        response = self.browser.open(urllib2.Request("https://developerservices2.apple.com/services/QH65B2/ios/downloadDevelopmentCert.action?clientId=" + self.clientId, plist, {'Content-Type': 'text/x-xml-plist'}))
        responseData = response.read()
        root = plistlib.readPlistFromString(responseData)
        return root["certificate"]["certContent"].data

    def revokeDevelopmentCert(self, serialNumber):
        requestId = str(uuid.uuid4()).upper()
        postData = {"clientId": self.clientId,
                    "myacinfo": self.accountBlob,
                    "protocolVersion": "QH65B2",
                    "requestId": requestId,
                    "teamId": self.teamId,
                    "serialNumber": serialNumber,
                    "userLocale": ["en_US"]}
        plist = plistlib.writePlistToString(postData)
        response = self.browser.open(urllib2.Request("https://developerservices2.apple.com/services/QH65B2/ios/revokeDevelopmentCert.action?clientId=" + self.clientId, plist, {'Content-Type': 'text/x-xml-plist'}))

    def submitDevelopmentCSR(self, csr):
        requestId = str(uuid.uuid4()).upper()
        postData = {"clientId": self.clientId,
                    "myacinfo": self.accountBlob,
                    "protocolVersion": "QH65B2",
                    "requestId": requestId,
                    "teamId": self.teamId,
                    "csrContent": csr,
                    "userLocale": ["en_US"]}
        plist = plistlib.writePlistToString(postData)
        response = self.browser.open(urllib2.Request("https://developerservices2.apple.com/services/QH65B2/ios/submitDevelopmentCSR.action?clientId=" + self.clientId, plist, {'Content-Type': 'text/x-xml-plist'}))
        responseData = response.read()
        root = plistlib.readPlistFromString(responseData)
        return root["certRequest"]

    def retrieveDevelopmentCerts(self):
        requestId = str(uuid.uuid4()).upper()
        postData = {"clientId": self.clientId,
                    "myacinfo": self.accountBlob,
                    "protocolVersion": "QH65B2",
                    "requestId": requestId,
                    "teamId": self.teamId,
                    "userLocale": ["en_US"]}
        plist = plistlib.writePlistToString(postData)
        response = self.browser.open(urllib2.Request("https://developerservices2.apple.com/services/QH65B2/ios/listAllDevelopmentCerts.action?clientId=" + self.clientId, plist, {'Content-Type': 'text/x-xml-plist'}))
        responseData = response.read()
        root = plistlib.readPlistFromString(responseData)
        return root["certificates"]

    def addDevice(self, deviceNumber):
        requestId = str(uuid.uuid4()).upper()
        postData = {"clientId": self.clientId,
                    "myacinfo": self.accountBlob,
                    "protocolVersion": "QH65B2",
                    "requestId": requestId,
                    "teamId": self.teamId,
                    "deviceNumber": deviceNumber,
                    "name": deviceNumber,
                    "userLocale": ["en_US"]}
        plist = plistlib.writePlistToString(postData)
        response = self.browser.open(urllib2.Request("https://developerservices2.apple.com/services/QH65B2/ios/addDevice.action?clientId=" + self.clientId, plist, {'Content-Type': 'text/x-xml-plist'}))
        responseData = response.read()
        root = plistlib.readPlistFromString(responseData)
        return root
    
    def retrieveActiveTeam(self):
        requestId = str(uuid.uuid4()).upper()
        postData = {"clientId": self.clientId,
                    "myacinfo": self.accountBlob,
                    "protocolVersion": "QH65B2",
                    "requestId": requestId,
                    "userLocale": ["en_US"]}
        plist = plistlib.writePlistToString(postData)
        response = self.browser.open(urllib2.Request("https://developerservices2.apple.com/services/QH65B2/listTeams.action?clientId=" + self.clientId, plist, {'Content-Type': 'text/x-xml-plist'}))
        responseData = response.read()
        root = plistlib.readPlistFromString(responseData)
        teams = root["teams"]
        for team in teams:
            if team["status"] == "active":
                return team

        logger.error("No active teams listed on the account")

    def login(self):
        postData = {"appIdKey": self.appIdKey,
                    "userLocale": "en_US",
                    "protocolVersion": "A1234",
                    "appleId": self.account_username,
                    "password": self.account_password,
                    "format": "json"}

        response = self.browser.open("https://idmsa.apple.com/IDMSWebAuth/clientDAW.cgi", urllib.urlencode(postData))
        parsedData = json.loads(response.read())
        if parsedData["resultCode"] == "0":
            logger.info("Logged into Apple Developer Center")
            self.accountBlob = parsedData["myacinfo"]
            ck = cookielib.Cookie(version=0, name='myacinfo', value=parsedData['myacinfo'], port=None, port_specified=False, domain='apple.com', domain_specified=False, domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
            self.cookiejar.set_cookie(ck)
        else:
            logger.info("Login Failed: %s" % parsedData["resultString"])

    def process(self):
        # login to apple id
        self.login()
        
        # set up teamId
        team = self.retrieveActiveTeam()
        self.teamId = team["teamId"]
        
        # view development certificates
        certs = self.retrieveDevelopmentCerts()
        if len(certs) == 0 or not os.path.exists(os.path.join(os.path.join('.', 'csr'), 'dev.cer')):
            if len(certs) == 1:
                # revoke existing certificate
                self.revokeDevelopmentCert(certs[0]["serialNumber"])
                logger.info("Revoked existing certificate")

            logger.info("Generating certificate request")
            name = team["name"]
            cn = "iOS Developer: %s (%s)" % (name, name)

            handle = certificate.GenCsr()
            csr = handle.type_RSA(cn, self.account_username, 'iOS Development', 'New York', 'New York', 'US', 2048, 'sha1')
            logger.info("Submitting development CSR...")
            submitResponse = self.submitDevelopmentCSR(csr)
            logger.info("Submission Status: %s", submitResponse["statusString"])
            if submitResponse["statusCode"] != 1:
                logger.error("Unable to get CSR approved")
                handle._clean_old_files()
                sys.exit(0)                

            # download development certificate
            devCert = self.downloadDevelopmentCert()
            if os.path.exists(os.path.join(os.path.join('.', 'csr'), 'dev.cer')):
                os.remove(os.path.join(os.path.join('.', 'csr'), 'dev.cer'))
            fh = open(os.path.join(os.path.join('.', 'csr'), 'dev.cer'), "w")
            fh.write(devCert)
            fh.close()
            logger.info("Saved development certificate to csr/dev.cer")

        # add device
        resp = self.addDevice(self.udid)
        if resp["resultCode"] == 0:
            logger.info("Device: %s was added to the Dev Center" % self.udid)
        elif resp["resultCode"] == 35:
            logger.info("Device: %s was already added to the Dev Center. Reason: %s" % (self.udid, resp["userString"]))
        else:
            logger.error("Unable to add device: %s to the Dev Center. Reason: %s" % (self.udid, resp["userString"]))
            sys.exit(0)
        
        # see if appId exists already on account
        appIdId = ""
        appIds = self.listAppIds()
        for appId in appIds:
            # self.removeAppId(appId["appIdId"])
            if appId["identifier"] == self.app_id:
                appIdId = appId["appIdId"]
                logger.info("Found existing app identifier: %s", self.app_id)
                break
        
        if appIdId == "":
            # add appId
            resp = self.addAppId(self.app_id)
            if resp["resultCode"] == 0:
                appIdId = resp["appId"]["appIdId"]
                logger.info("Added app identifier: %s", self.app_id)
            else:
                logger.info("Unable to add app identifier: %s. Reason: %s" % (self.app_id, resp["userString"]))
                sys.exit(0)
        
        # download provisioning profile
        resp = self.downloadProvisioningProfile(appIdId)
        profileData = resp["encodedProfile"].data
        if os.path.exists(os.path.join('.', 'profile.mobileprovision')):
            os.remove(os.path.join('.', 'profile.mobileprovision'))
        fh = open(os.path.join('.', 'profile.mobileprovision'), "w")
        fh.write(profileData)
        fh.close()
        logger.info("Saved provisioning profile to ./profile.mobileprovision")

        # delete app id
        self.removeAppId(appIdId)
        logger.info("Removed App ID: %s", appIdId)

# create logger
logger = logging.getLogger("sideload")
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

parser = argparse.ArgumentParser(description='Create free provisioning for sideloading on iOS devices.')
parser.add_argument('username',
                   help='Apple ID (developer) email')
parser.add_argument('password',
                   help='Apple ID (developer) password')
parser.add_argument('udid',
                   help='iOS device UDID')
parser.add_argument('appid',
                   help='A unique bundle identifier')
args = parser.parse_args()

if args.username and args.password and args.udid and args.appid:
    print ""
    sl = sideload(args.username, args.password, args.udid, args.appid)
    sl.process()
