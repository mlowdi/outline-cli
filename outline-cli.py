#!/usr/bin/env python

import argparse
import json
import requests
import ssl
from requests_toolbelt.adapters.fingerprint import FingerprintAdapter
import urllib

ACCESS_PREAMBLE = "https://s3.amazonaws.com/outline-vpn/invite.html#"
servers = {}
server_names = []

# Outline servers use self-signed certs
# We're using requests_toolbelt to compare the certificate sha256 against the definition
# and will throw an error if they don't match
requests.packages.urllib3.disable_warnings()


def load_servers():
	"""Load list of servers from JSON file and populate server list.
	Server list format is [{"mnemonic":{output object from Outline setup}}, {...}]
	We'll be using both the servers and the server_names variables!"""
	global servers
	global server_names
	try:
		with open('servers.json','r') as handle:
			servers = json.load(handle)
		pass
	except Exception as e:
		raise e
	else:
		for key in servers:
			server_names.append(key)
		pass

def call_api(action, server, userid=False):
	"""Wrapper thing to call the API based on different actions."""
	if action == 'deluser' and not userid:
		raise Exception('Cannot call deluser without passing a User ID')

	# Construct the URL string to use and get the sha256 fp from the server definition
	urlline = [servers[server]['apiUrl'], '/access-keys']
	certfp = servers[server]['certSha256']

	# Mount adapter to verify fingerprint
	s = requests.Session()
	s.mount(urlline[0], FingerprintAdapter(certfp))

	if action == "adduser":
		try:
			r = s.post(''.join(urlline), verify=False)
			pass
		except Exception as e:
			raise e
	
	elif action == "deluser":
		urlline.append("/" + str(userid))
		try:
			r = s.delete(''.join(urlline), verify=False)
			pass
		except Exception as e:
			raise e
		else:
			if r.status_code == requests.codes.no_content:
				print "User key %s deleted successfully" % userid
			else:
				print "Unexpected status code: %s" % r.status_code
			pass
	
	elif action == "listusers":
		try:
			r = s.get(''.join(urlline), verify=False)
			pass
		except Exception as e:
			raise e
	else:
		raise Exception("%s is not a legal option!" % action)


	return r


def adduser(server):
	"""Takes a server ID and add a new user key on the server. Prints a pretty record of the new key for ease of sharing."""
	result = call_api('adduser', server)

	data = json.loads(result.text)
	prettyrecord(data)

def deluser(server, userid):
	"""Takes a server ID and a user key ID and deletes the key from the server. Will alert if you get anything but HTTP 204 in response."""
	result = call_api('deluser', server, userid)

def listusers(server):
	"""Takes a server ID and returns a pretty record of all user keys on the server."""
	result = call_api('listusers', server)

	data = json.loads(result.text)
	for key in data['accessKeys']:
		prettyrecord(key)

def prettyrecord(accesskey):
	"""Takes a JSON format access key record and prints a pretty version.
	Plays nice and listens to the -i switch to either print a one-click access link or not."""
	if arguments.i:
		s = "User ID: {0}\n\tName: {1}\n\tAccess URL: {2}\n\tInvite URL: {3}\n"
		print s.format(accesskey['id'], accesskey['name'], accesskey['accessUrl'], ACCESS_PREAMBLE + urllib.quote_plus(accesskey["accessUrl"]))
	else:
		s = "User ID: {0}\n\tName: {1}\n\tAccess URL: {2}\n"
		print s.format(accesskey['id'], accesskey['name'], accesskey['accessUrl'])


if __name__ == '__main__':
	# Argparse setup (takes the server list, so we invoke it first)
	load_servers()
	parser = argparse.ArgumentParser(description='Fleet management for Outline VPN servers')
	parser.add_argument('-s', '--server', required=True, help='Server to take action on', choices=server_names)
	actions = parser.add_mutually_exclusive_group(required=True)
	actions.add_argument('-a', '--adduser', action='store_true', help="Create a user key on server")
	actions.add_argument('-d', '--deluser', metavar='ID', type=int, help="Delete user key with given ID from server")
	actions.add_argument('-l', '--list', action='store_true', help="List all user keys on server")
	parser.add_argument('-n', metavar='name', help="Set a friendly name for the newly created user")
	parser.add_argument('-i', action='store_true', help="Add one-click invitation links to output")

	arguments = parser.parse_args()


	# Invoke correct function
	if arguments.adduser:
		print "Creating a user on server %s" % (arguments.server)
		adduser(arguments.server)

	if arguments.deluser:
		print "Deleting user key number %s from server %s" % (arguments.deluser, arguments.server)
		deluser(arguments.server, arguments.deluser)

	if arguments.list:
		print "Listing user keys on server %s" % arguments.server
		listusers(arguments.server)

