#!/usr/bin/env python

import argparse
import json
import requests
import urllib

ACCESS_PREAMBLE = "https://s3.amazonaws.com/outline-vpn/invite.html#"

# We know what we're doing, we don't need warnings
# Outline servers use self-signed certs
# TODO: figure out how to verify the cert agains the sha256 sum in the server definition
requests.packages.urllib3.disable_warnings()

# Load list of servers from JSON file and populate server list
# We'll be using both the servers and the server_list variables!
try:
	with open('servers.json','r') as handle:
		servers = json.load(handle)
	pass
except Exception as e:
	raise e
else:
	pass

server_list = []
for key in servers:
	server_list.append(key)

def adduser(server):
	"""Takes a server ID and add a new user key on the server. Prints a pretty record of the new key for ease of sharing."""
	try:
		r = requests.post(servers[server]['apiUrl'] + "/access-keys", verify=False)
		pass
	except Exception as e:
		raise e

	data = json.loads(r.text)
	prettyrecord(data)

def deluser(server, userid):
	"""Takes a server ID and a user key ID and deletes the key from the server. Will alert if you get anything but HTTP 204 in response."""
	try:
		r = requests.delete(servers[server]['apiUrl'] + "/access-keys/%s" % userid, verify=False)
		pass
	except Exception as e:
		raise e

	if r.status_code == requests.codes.no_content:
		print "User key %s deleted successfully" % userid
	else:
		print "Unexpected status code: %s" % r.status_code

def listusers(server):
	"""Takes a server ID and returns a pretty record of all user keys on the server."""
	try:
		r = requests.get(servers[server]['apiUrl'] + "/access-keys", verify=False)
		pass
	except Exception as e:
		raise e

	data = json.loads(r.text)
	for key in data['accessKeys']:
		prettyrecord(key)

def prettyrecord(accesskey):
	"""Takes a JSON format access key record and prints a pretty version."""
	s = """User ID: {0}
	Name: {1}
	Access URL: {2}
	Invite URL: {3}
	"""
	print s.format(accesskey['id'], accesskey['name'], accesskey['accessUrl'], ACCESS_PREAMBLE + urllib.quote_plus(accesskey["accessUrl"]))

# Argparse setup (takes the server def so we can't invoke it at the very top...)
parser = argparse.ArgumentParser(description='Fleet management for Outline VPN servers')
parser.add_argument('-s', '--server', required=True, help='Server to take action on', choices=server_list)
actions = parser.add_mutually_exclusive_group(required=True)
actions.add_argument('-a', '--adduser', action='store_true', help="Create a user key on server")
actions.add_argument('-d', '--deluser', metavar='ID', help="Delete user key with given ID from server")
actions.add_argument('-l', '--list', action='store_true', help="List all user keys on server")

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

