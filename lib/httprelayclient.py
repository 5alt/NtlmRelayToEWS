#!/usr/bin/python
# Copyright (c) 2003-2016 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Modified by Arno0x0x for handling NTLM relay to EWS server
#
# Author:
#   Dirk-jan Mollema / Fox-IT (https://www.fox-it.com)
#
# Description: 
# HTTP(s) client for relaying NTLMSSP authentication to webservers
#
import logging
import re
import requests
import base64

class HTTPRelayClient:
	#-------------------------------------------------------------------------------
    def __init__(self, target, body):
        # Target comes as protocol://target:port/path
        self.target = target
        proto, host, path = target.split(':')
        host = host[2:]
        self.path = '/' + path.split('/', 1)[1]
        self.body = body
        self.session = requests.Session()
        #self.session.proxies = {'http': 'http://127.0.0.1:8080'}
        self.lastresult = None

	#-------------------------------------------------------------------------------
    def sendNegotiate(self,negotiateMessage):
		#Check if server wants auth
		if self.body is not None:
			res = self.session.post(self.target, self.body, headers={"Content-Type":"text/xml"})
		else:
			res = self.session.get(self.target)

		if res.status_code != 401:
			logging.info('Status code returned: %d. Authentication does not seem required for URL' % res.status_code)
		try:
			if 'NTLM' not in res.headers.get('WWW-Authenticate', ''):
				logging.error('NTLM Auth not offered by URL, offered protocols: %s' % res.headers.get('WWW-Authenticate'))
				return False
		except KeyError:
			logging.error('No authentication requested by the server for url %s' % self.target)
			return False

		#Negotiate auth
		negotiate = base64.b64encode(negotiateMessage)
		if self.body is not None:
			headers = {'Authorization':'NTLM %s' % negotiate, "Content-Type":"text/xml"}
			res = self.session.post(self.target, self.body, headers=headers)
		else:
			headers = {'Authorization':'NTLM %s' % negotiate}
			res = self.session.get(self.target, headers=headers)

		try:
			serverChallengeBase64 = re.search('NTLM ([a-zA-Z0-9+/]+={0,2})', res.headers.get('WWW-Authenticate', '')).group(1)
			serverChallenge = base64.b64decode(serverChallengeBase64)
			return serverChallenge
		except (IndexError, KeyError, AttributeError):
			logging.error('No NTLM challenge returned from server')

	#-------------------------------------------------------------------------------
    def sendAuth(self,authenticateMessageBlob, serverChallenge=None):
		#Negotiate auth
		auth = base64.b64encode(authenticateMessageBlob)
		if self.body is not None:
			headers = {'Authorization':'NTLM %s' % auth, "Content-Type":"text/xml"}
			res = self.session.post(self.target, self.body, headers=headers)
		else:
			headers = {'Authorization':'NTLM %s' % auth}
			res = self.session.get(self.target, headers=headers)
			
		if res.status_code == 401:
			return False
		else:
			logging.info('HTTP server returned error code %d, treating as a succesful login' % res.status_code)
			#Cache this
			self.lastresult = res.text
			return True

	#-------------------------------------------------------------------------------
    #SMB Relay server needs this
    @staticmethod
    def get_encryption_key():
        return None
