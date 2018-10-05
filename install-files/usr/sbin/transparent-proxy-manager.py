#!/usr/bin/env python3
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GObject, Gdk
import shutil
import os
import subprocess
import time
import threading
import sys

import gettext
gettext.textdomain('zero-lliurex-transparent-proxy')
_ = gettext.gettext

class squidManager():
	def __init__(self,callback):
		threading.Thread.__init__(self)
		self.systemSquid="squid"
		self.sslSquid="squid-ssl"
		self.systemSquidConf="/etc/squid/squid.conf"
		self.sslSquidConf="/etc/squid-ssl/squid.conf"
		self.sslCert="/etc/squid-ssl/ssl_cert/lliurexCA.pem"
		self.systemSquidService="squid"
		self.sslSquidService="squid-ssl"
		self.server_ip=''
		self.sslPort=3129
		self.dbg=0
		self.callback=callback
		self.iptablesRulesFile='/usr/share/iptables/rules/transparent.rules'
	#def __init__

	def _debug(self,msg):
		if self.dbg==1:
			print("DBG: "+str(msg))
	#def _debug

	def _exe_cmd(self,cmd,output=os.devnull):
		status=-1
		self._debug("Executing "+cmd)
		try:
			with open(output, 'wb') as hide_output:
				if "|" in cmd:
					status = subprocess.Popen(cmd.split(' '), stdout=hide_output, stderr=hide_output,shell=True).wait()
				else:
					status = subprocess.Popen(cmd.split(' '), stdout=hide_output, stderr=hide_output).wait()
		except:
			status=1
		self._debug("$?: "+str(status))
		return status
	#def _exe_cmd

	def enable_transparent_proxy(self):
		self._debug("Enabling proxy")
		if not self._is_squidssl_installed():
			self._install_squidssl()
		if not self.is_service_running(self.sslSquidService):
			self._generate_SSL_cert()
			#Copy the original squid.conf and make the needed changes
			self._generate_SquidSSl_config()
			#Add iptables redirection
			self._add_iptables_redirection()
			#Disable squid
			self._disable_service(self.systemSquidService)
			#Enable squid-ssl
			self._debug("Enabling "+self.sslSquidService+" service")
			self._enable_service(self.sslSquidService)
		else:
			self._debug("Service is already running")
		GObject.idle_add(self.callback,1)
	#def enable_transparent_proxy
				
	def _generate_SquidSSl_config(self):
		self._debug("Configuring "+self.sslSquidService)
		try:
			shutil.copy (self.systemSquidConf,self.sslSquidConf)
			f=open(self.sslSquidConf,"r")
			squidConfOrig=f.readlines()
			f.close()
			squidConfMod=[]
			net_ip=''
			for line in squidConfOrig:
				if line.startswith("http_port"):
					if '127.0.' not in line:
						server_ip=line.split(' ')[1]
						self.server_ip=server_ip.split(':')[0]
						lineHttps="##Transparent https -->\nhttps_port "+self.server_ip+":"+str(self.sslPort)+" intercept ssl-bump generate-host-certificates=on dynamic_cert_mem_cache_size=4MB cert="+self.sslCert+" key="+self.sslCert+"\n#ssl_bump client-first all\nssl_bump splice all\n## <--"
						line=line.rstrip("\n")+" intercept\n"
						line=line+lineHttps
				squidConfMod.append(line)
			f=open(self.sslSquidConf,"w")
			f.writelines(squidConfMod)
			f.close()
		except Exception as e:
			print(str(e))
	#def _generate_SquidSSl_config

	def _generate_SSL_cert(self):
		if not os.path.isfile(self.sslCert):
			if not os.path.isdir(os.path.dirname(self.sslCert)):
				os.makedirs(os.path.dirname(self.sslCert))
			self._exe_cmd('openssl req -new -newkey rsa:1024 -days 365 -nodes -x509 -extensions v3_ca -keyout '+self.sslCert+' -out '+self.sslCert+' -batch')
		#Initialize directory for caching certificates
		ssl_db='/var/lib/ssl_db'
		self._exe_cmd('/usr/lib/squid-ssl/ssl_crtd-ssl -c -s '+ssl_db)
		#Change owner of ssl_db dir
		shutil.chown(ssl_db,user="nobody")
	#def _generate_SSL_cert

	def _add_iptables_redirection(self):
		self._debug("Adding iptables rules")
		net_ip=self.server_ip.split('.')[0:3]
		net_ip='.'.join(net_ip)+".0"
		self._exe_cmd('iptables -t nat -A PREROUTING -s '+net_ip+'/16 -p tcp -m tcp --dport 443 -j REDIRECT --to-ports '+str(self.sslPort))
		self._exe_cmd('iptables -t nat -A PREROUTING -s '+net_ip+'/16 -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 3128')
		#Save the rules files
		if not os.path.isdir(os.path.dirname(self.iptablesRulesFile)):
			os.makedirs(os.path.dirname(self.iptablesRulesFile))
		print("Saving iptables to %s"%self.iptablesRulesFile)
		cmd='iptables-save -t nat'
		self._exe_cmd(cmd,self.iptablesRulesFile)
		print("Saved")

	#def _add_iptables_redirection

	def disable_transparent_proxy(self):
		if self.is_service_running(self.sslSquidService):
			#stop the service
			self._disable_service(self.sslSquidService)
		#Clean the firewall
		try:
			self._exe_cmd('iptables -t nat -F')
			os.remove(self.iptablesRulesFile)
		except Exception as e:
			print(str(e))
		#Remove the conf files
		self._debug("Removing config files")
		if os.path.isfile(self.sslSquidConf):
			os.remove(self.sslSquidConf)
		#Restore system's squid
		self._enable_service(self.systemSquidService)
		GObject.idle_add(self.callback)
	#def disable_transparent_proxy

	def _disable_service(self,service):
		self._debug("Disabling "+service)
		try:
			self._exe_cmd('service '+service+' stop')
			self._exe_cmd('update-rc.d '+service+' remove')
		except Exception as e:
			print(str(e))
	#def _disable_service

	def _enable_service(self,service):
		self._debug("Enabling "+service)
		try:
			self._exe_cmd("update-rc.d "+service+" defaults 30")
			self._exe_cmd("invoke-rc.d "+service+" restart")
		except Exception as e:
			print(str(e))
	#def _enable_service

	def is_service_running(self,name):
		retval=False
		try:
			status=self._exe_cmd('service '+name+' status')
			if status==0:
				retval=True
		except Exception as e:
			print(str(e))
		self._debug("Squid-ssl running: "+str(retval))
		return retval
	#def is_service_running

	def _is_squidssl_installed(self):
		retval=True
		status=-1
		try:
			status=self._exe_cmd('dpkg --get-selections squid-ssl | grep deinstall')
			if status==0:
				retval=False
			else:
			#If package has never been installed dpkg returns an error, so we need to recheck
				status=self._exe_cmd('dpkg -L squid-ssl')
				if status!=0:
					retval=False
		except Exception as e:
			print(str(e))
		self._debug("Squid-ssl installed: "+str(retval))
		self._debug(status)
		return retval
	#def _is_squidssl_installed

	def _install_squidssl(self):
		self._debug("Installing needed packages")
		self._exe_cmd('zero-repos-update')
		self._exe_cmd('zero-installer install squid-ssl')
	#def _install_squidssl

class mainWindow(Gtk.Window):
	def __init__(self):
		self.dbg=0
		Gtk.Window.__init__(self,title=_("Transparent Proxy"))
		self.set_position(Gtk.WindowPosition.CENTER)
		self.connect("delete-event", Gtk.main_quit)
		vbox=Gtk.VBox()
		img_area=Gtk.Box(spacing=6)
#		 img=Gtk.Image.new_from_file('/usr/share/icons/Vibrancy-Colors/status/36/network-receive.png')
		img=Gtk.Image(stock=Gtk.STOCK_DISCONNECT)
		img_area.add(img)
		img_area.add(Gtk.Label(_("Transparent proxy management")))
		img_area.set_border_width(5)
		img_area.show_all()
		frame=Gtk.Frame()
		frame.set_border_width(5)
#		 frame.set_label(_("Transparent proxy management"))
		box = Gtk.Grid()
		box.set_border_width(5)
		box.set_column_spacing(20)
		box.set_row_spacing(30)
		self.add(vbox)
		vbox.add(img_area)
		vbox.add(frame)
		frame.add(box)
		box.attach(Gtk.Label(_("Enable Transparent Proxy")),0,1,1,1)
		self.sw_Enable=Gtk.Switch()
		box.attach(self.sw_Enable,1,1,1,1)
		self.lbl_State=Gtk.Label('')
		box.attach(self.lbl_State,0,2, 3,2)
		self.spinner = Gtk.Spinner()
		box.attach(self.spinner, 0, 3, 2, 2)
		self.squidManager=squidManager(self._callback)
		self.sw_Enable.set_active(self.squidManager.is_service_running(self.squidManager.sslSquidService))
		if self.sw_Enable.get_state():
			service_label="Service up and running"
		else:
			service_label="Service deactivated"
		self.lbl_State.set_text(_(service_label))
		self.sw_Enable.connect("state-set",self._on_sw_state)
		self.show_all()
	#def __init__
				
	def _debug(self,msg):
		if self.dbg==1:
			print("DBG: "+str(msg))
	#def _debug

	def _on_sw_state(self,widget,data):
		self._debug("State changed")
		widget.set_sensitive(False)
		self.spinner.start()
		sw_state=widget.get_state()
		if not sw_state:
			self._debug("Enabling transparent proxy")
			self.lbl_State.set_text(_("Enabling transparent proxy"))
			th=threading.Thread(target=self.squidManager.enable_transparent_proxy)
			th.start()
		else:
			self.lbl_State.set_text(_("Disabling transparent proxy"))
			th=threading.Thread(target=self.squidManager.disable_transparent_proxy)
			th.start()
		self._debug("Done")
	#def _on_sw_state

	def _callback(self,action=None):
		self.spinner.stop()
		if action:
			self.lbl_State.set_text(_("Service up and running"))
		else:
			self.lbl_State.set_text(_("Service deactivated"))
		self.sw_Enable.set_sensitive(True)
	#def _callback

def read_key():
	try:
		f=open("/etc/n4d/key")
		f.close()
		#hack
		return True
	except:
		return False

status=read_key()

if not status:
	print("[!] You need root privileges to run this program [!]")
	label = Gtk.Label(_("You need root privileges to run transparfent-proxy-manager"))
	dialog = Gtk.Dialog("Warning", None, Gtk.DialogFlags.MODAL | Gtk.DialogFlags.DESTROY_WITH_PARENT, (Gtk.STOCK_OK, Gtk.ResponseType.ACCEPT))
	dialog.vbox.pack_start(label,True,True,10)
	label.show()
	dialog.set_border_width(6)
	response = dialog.run()
	dialog.destroy()
	sys.exit(0)

GObject.threads_init()
Gdk.threads_init()
win = mainWindow()
Gtk.main()
