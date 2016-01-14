#!/usr/bin/env python
# -*- encoding: utf-8 -*-

""" Detect machine LAN """

import sys
import nmap
import re
import os
import smtplib
import time,datetime
import gtk
from optparse import OptionError
from optparse import OptionGroup
from optparse import OptionParser

__author__ 		= "GoldraK"
__credits__ 	= "GoldraK"
__version__ 	= "0.1"
__maintainer__ 	= "GoldraK"
__email__ 		= "goldrak@gmail.com"
__status__ 		= "Development"


class DetectMachineLan():

	def __init__(self):
		self.version = "0.1"
		self.whitelist_file = ""
		self.log = False
		self.verbose = False



	def DetectMachineLan(self):
		(opts, args) = self.__handleArguments()
		if opts.macsearch and opts.ip:
			self.__detectMachinesNetwork(opts.ip)
		if opts.macadd:
			macs = opts.macadd.split(",")
			for x in macs:
				self.__writeWhitelist(x)
		if opts.macremove:
			macs = opts.macremove.split(",")
			for x in macs:
				self.__removeWhitelist(x)
		if opts.ip and opts.macsearch == False:
			self.__detectMachinesWhitelist(opts)


	def __scanNetwork(self,ip):
		nm = nmap.PortScanner()
		machines=nm.scan(hosts=ip, arguments='-sP') 
		return machines

	def __detectMachinesNetwork(self,ip):
		machines = self.__scanNetwork(ip)
		for k,v in machines['scan'].iteritems(): 
			if str(v['status']['state']) == 'up':
				print "-------"
				try:   
					print str(v['addresses']['ipv4'])+" --> "+str(v['addresses']['mac'])
				except: 
					print str(v['addresses']['ipv4'])+" --> Mac no detected"

	def __detectMachinesWhitelist(self,opts):
		whitelist = self.__read_file()

		alert_mac = ""

		machines = self.__scanNetwork(opts.ip)

		for k,v in machines['scan'].iteritems(): 
			if str(v['status']['state']) == 'up':
				#print str(v)
				try:   
					if str(v['addresses']['mac']) in whitelist:
						msg = 'Mac find '+str(v['addresses']['mac'])+' Ip: '+str(v['addresses']['ipv4'])
						if self.verbose:
							self.__consoleMessage(msg)
						if self.log:
							self.__writeLog(msg)
					else:
						alert_mac = alert_mac+'New mac detected '+str(v['addresses']['mac'])+' Ip: '+str(v['addresses']['ipv4'])+'\n'
						msg = 'New mac detected '+str(v['addresses']['mac'])+' Ip: '+str(v['addresses']['ipv4'])
						if self.verbose:
							self.__consoleMessage(msg)						
						if self.log:
							self.__writeLog(msg)

				except: 
					msg = 'Mac not detected '+str(v['addresses']['ipv4'])
					if self.verbose:
						self.__consoleMessage(msg)						
					if self.log:
						self.__writeLog(msg)
		if opts.emailto:
			self.__sendEmail(alert_mac,opts)
		if opts.gtk:
			self.__gtkinfo(alert_mac)



	def __handleArguments(self,argv=None):
		"""
		This function parses the command line parameters and arguments
		"""

		parser = OptionParser()
		if not argv:
			argv = sys.argv

		mac = OptionGroup(parser, "Mac", "At least one of these "
			"options has to be provided to define the machines")

		mac.add_option('--ms','--macsearch', action='store_true', default=False, dest='macsearch', help='Search machine Network')
		mac.add_option('--ma','--macadd', action='store', dest='macadd', help='Add mac to whitelist')
		mac.add_option('--mr','--macremove', action='store', dest='macremove', help='Remove mac from whitelist')


		email = OptionGroup(parser, "Email", "You need user,password,server and destination"
			"options has to be provided to define the server send mail")

		email.add_option('-u','--user', action='store', dest='user', help='User mail server')
		email.add_option('--pwd','--password', action='store', dest='password', help='Password mail server')
		email.add_option('-s','--server', action='store', dest='server', help='mail server')
		email.add_option('-p','--port', action='store', default='25', dest='port', help='Port mail server')
		email.add_option('--et','--emailto', action='store', dest='emailto', help='Destination E-mail')


		parser.add_option('-r','--range', action='store', dest='ip', help='Secure network range ')
		parser.add_option('--wl','--whitelist', action='store', default='whitelist.txt' , dest='whitelist_file', help='File have Mac whitelist ')
		parser.add_option('-l','--log', action='store_true', default=False, dest='log', help='Log acctions script')
		parser.add_option('-v','--verbose', action='store_true', default=False, dest='verbose', help='Verbose acctions script')
		parser.add_option('-g','--gui', action='store_true', default=False, dest='gtk', help='GTK Windows with info')


		parser.add_option_group(mac)
		parser.add_option_group(email)

		(opts, args) = parser.parse_args()

		self.log = opts.log
		self.verbose = opts.verbose
		self.whitelist_file = opts.whitelist_file

		if opts.user or opts.password or opts.server or opts.emailto:
			if not all([opts.user, opts.password,opts.server,opts.emailto]):
				errMsg = "missing some email option (-u, --pwd, -s, --et), use -h for help"				
				parser.error(errMsg)
				self.__writeLog(errMsg)
				sys.exit(-1)
		if opts.macsearch and not opts.ip:
			errMsg = "missing some range scan option (-r), use -h for help"
			parser.error(errMsg)
			self.__writeLog(errMsg)
			sys.exit(-1)
		return opts, args


	def __sendEmail(self,alert_mac,opts):
		"""
		This function send mail with the report
		"""
		header  = 'From: %s\n' % opts.user
		header += 'To: %s\n' % opts.emailto
		if alert_mac:
			header += 'Subject: New machines connected\n\n'
			message = header + 'List macs: \n '+str(alert_mac)
		else:
			header += 'Subject: No intruders - All machines known \n\n'
			message = header + 'No intruders'

		server = smtplib.SMTP(opts.server+":"+opts.port)
		server.starttls()
		server.login(opts.user,opts.password)
		if self.verbose or self.log:
			debugemail = server.set_debuglevel(1)
			if self.verbose:
				self.__consoleMessage(debugemail)
		problems = server.sendmail(opts.user, opts.emailto, message)
		print problems
		server.quit()

	def __gtkinfo(self,alert_mac):
		parent = None
		if alert_mac:
			md = gtk.MessageDialog(parent, 
				gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_WARNING, 
				gtk.BUTTONS_CLOSE, 'List macs: \n '+str(alert_mac))
		else:
			md = gtk.MessageDialog(parent, 
				gtk.DIALOG_DESTROY_WITH_PARENT, gtk.MESSAGE_INFO, 
				gtk.BUTTONS_CLOSE, "No intruders - All machines known")
		md.run()


	def __consoleMessage(self,message):
		ts = time.time()
		st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
		print '['+st+'] '+str(message)


	def __writeLog(self,log):
		"""
		This function write log
		"""
		ts = time.time()
		st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
		if os.path.isfile('log.txt'):
			try:
				file_read = open('log.txt', 'a')
				file_read.write('['+st+'] '+log+"\n")
				file_read.close()
			except IOError:
				msg = 'ERROR: Cannot open'+ self.whitelist_file
				if self.verbose:
					self.__consoleMessage(msg)
				sys.exit(-1)
		else:
			msg = "ERROR: The Whitelist file ", self.whitelist_file, " doesn't exist!"
			if self.verbose:
				self.__consoleMessage(msg)
			sys.exit(-1)


	def __writeWhitelist(self,mac):
		"""
		This function add newmac to whitelist
		"""
		if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
			if os.path.isfile(self.whitelist_file):
				try:
					file_read = open(self.whitelist_file, 'a')
					file_read.write(mac+"\n")
					file_read.close()
					msg = "Mac: "+ mac + " add correctly"
					if self.verbose:
						self.__consoleMessage(msg)
					if self.log:
						self.__writeLog(msg) 
				except IOError:
					print 
					msg = 'ERROR: Cannot open'+ self.whitelist_file
					if self.verbose:
						self.__consoleMessage(msg)
					if self.log:
						self.__writeLog(msg) 
					sys.exit(-1)
			else:
				msg = "ERROR: The Whitelist file "+ self.whitelist_file+ " doesn't exist!"
				if self.verbose:
					self.__consoleMessage(msg)
				if self.log:
					self.__writeLog(msg) 
				sys.exit(-1)
		else:
			msg = "ERROR: The Mac "+ mac +" not valid!"
			if self.verbose:
				self.__consoleMessage(msg)
			if self.log:
				self.__writeLog(msg) 

	def __removeWhitelist(self,mac):
		"""
		This function remove newmac from whitelist
		"""
		if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower()):
			if os.path.isfile(self.whitelist_file):
				try:
					file_read = open(self.whitelist_file, 'r')
					lines = file_read.readlines()
					file_read.close()
					file_read = open(self.whitelist_file, 'w')
					for line in lines:
						if line.strip() != mac:
							file_read.write(line)
					file_read.close()
					msg = "Mac "+mac+" remove correctly"
					if self.verbose:
						self.__consoleMessage(msg)
					if self.log:
						self.__writeLog(msg) 
				except IOError:
					msg = 'ERROR: Cannot open '+ self.whitelist_file
					if self.verbose:
						self.__consoleMessage(msg)
					if self.log:
						self.__writeLog(msg) 
					sys.exit(-1)
			else:
				msg = "ERROR: The Whitelist file "+ self.whitelist_file+ " doesn't exist!"
				if self.verbose:
					self.__consoleMessage(msg)
				if self.log:
					self.__writeLog(msg) 
				sys.exit(-1)
		else:
			msg = "ERROR: The Mac "+ mac + " doesn't exist!"
			if self.verbose:
				self.__consoleMessage(msg)
			if self.log:
				self.__writeLog(msg) 

	def __read_file(self):
		"""
		This function read the whitelist
		"""
		whitelist = []
		if os.path.isfile(self.whitelist_file):
			try:
				file_read = open(self.whitelist_file, 'r')
				for line in file_read:
					if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", line.strip().lower()):
							whitelist.append(line.strip())
				return whitelist
			except IOError:
				msg = 'ERROR: Cannot open '+ self.whitelist_file
				if self.verbose:
					self.__consoleMessage(msg)
				if self.log:
					self.__writeLog(msg) 
				sys.exit(-1)
		else:
			msg = "ERROR: The Whitelist file "+ self.whitelist_file+ " doesn't exist!"
			if self.verbose:
				self.__consoleMessage(msg)
			if self.log:
				self.__writeLog(msg) 
			sys.exit(-1)




if __name__ == "__main__":
	p = DetectMachineLan()
	p.DetectMachineLan()