##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'ColdFusion Server Check',
			'Version'     => '$Revision:$',
			'Description' => %q{
				This module scans for common ColdFusion URLS for admin login and FCKeditor.
			},
			'References'  =>
			[
				[ 'URL', 'http://carnal0wnage.attackresearch.com' ],
			],
			'Author'      => [ 'CG' ],
			'License'     => MSF_LICENSE
			)

	register_options([Opt::RPORT(80),], self.class)
	
	end

	def run_host(ip)
#time to blow up the IPS/IDS
		path = [
	"/index.cfm", #basically verify its some sort of CFML
	"/%2500.cfm",
	"/%00.cfm",
	"%00.cfm",
	"/nul.dbm", #nessus plugin 11383 for CF Path disclosure
	"/null.dbm", #nessus plugin 11383 for CF Path disclosure
	"/version.txt",
    	"/CFIDE/administrator/index.cfm", #Admin Login Portal
	"/CFIDE/administrator/logging/settings.cfm?locale=../../../../sha1.js%00en", #locale traversal check
   	"/CFIDE/componentutils/login.cfm", #Used for RDS type logins, can be used to validate passwords.  See coldfustion_rds_bf.rb
	"/CFIDE/componentutils/login.cfm?_cf_containerID=blahblah'",
    	"/CFIDE/scripts/ajax/FCKeditor/editor/dialog/fck_about.html", #FCKeditor version disclosure
	"/CFIDE/scripts/ajax/FCKeditor/fckeditor.cfm", #look for path disclsoure in 500 error
	"/CFIDE/componentutils/packagelist.cfm", #installed packages
	"/CFIDE/probe.cfm", #If Debug is on, may disclosure Path information
	"/CFIDE/wizards/common/_authenticatewizarduser.cfm", #Another place to try logins
	"/CFIDE/wizards/common/_logintowizard.cfm?%3C%22'%3E",
	"/CFIDE/wizards/common/_logintowizard.cfm?<\"'>",
	"/CFIDE/wizards/common/utils.cfc?method=verifyldapserver&vserver=localhost&vport=389&vstart=&vusername=&vpassword=&returnformat=json",
	"/CFIDE/debug/cf_debugFr.cfm?userPage=http%3A%2F%2Fgoogle.com",
	"/404_106321.cfm",
	"/CFIDE/adminapi/base.cfc?wsdl", #WDSL file, CF version
	"/CFIDE/scripts/cfform.js", #dont know... from freitag scanner
	"/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/cf5_connector.cfm?command=GetFoldersAndFiles&type=Image&currentFolder=/",
	"/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/cf_connector.cfm?command=GetFoldersAndFiles&type=Image&currentFolder=/",
	"/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/upload/cfm/upload.cfm",
	"/CFIDE/scripts/ajax/FCKeditor/editor/dialog/fck_spellerpages/spellerpages/server-scripts/spellchecker.cfm",
	"/FCKeditor/editor/filemanager/connectors/cfm/cf_connector.cfm?command=GetFoldersAndFiles&type=Image&currentFolder=/",
	"/FCKeditor/editor/filemanager/connectors/cfm/cf5_connector.cfm?command=GetFoldersAndFiles&type=Image&currentFolder=/",
	"/flashservices/gateway",
	"/CFFormGateway/",
	"/CFIDE/GraphData.cfm",
	"/CFFileServlet/",
	"/cfform-internal",
	"/script/databases/makered.mdb",	#http://osvdb.org/show/osvdb/53229
	"/script/databases/makered97.mdb", #http://osvdb.org/show/osvdb/53229
	"/WSRPProducer/",
	"/railo-context/admin/web.cfm", #Railo (opensource coldfusion) web admin login
	"/railo-context/admin/server.cfm", #Railo (opensource coldfusion) server admin login
	"/railo-context/test.cfm", #Railo
	"/railo-context/templates/display/debugging-console.cfm", #Railo debug info
	"/railo-context/templates/display/debugging-console-output.cfm?requestID=1", #?requestID=1&_debug_action=store
	"/railo-context/templates/display/debugging-console-output.cfm?requestID=1&_debug_action=store",
	"/_mmServerScripts/MMSERVERINFO.cfm",  #gotta look it up
	"/admin/index.cfm?fuseaction=cLogin.main", #Mura admin login page
	"/bluedragon.xml.bak.1", #bluedragon config files
	"/bluedragon.xml", #bluedragon config files
	"/bluedragon/admin.cfm", #bluedragon admin console
	"/manager/status", #railo admin status splash page. links to tomcat admin and railo admin
#JRUN fuzz
	"/compass/logon.jsp",
	"/databasenotes.html",
	"/flash/java/javabean/FlashJavaBean.html",
	"/jrunscripts",
	"/jstl-war/index.html",
	"/SmarTicketApp/index.html",
	"/techniques/servlets/index.html",
	"/travelnet/home.jsp",
	"/WEB-INF/webapp.properties",
	"/WEB-INF/web.xml",
	"/worldmusic/action/catalog",
	"/worldmusic/action/cdlist",
	"/ws-client/loanCalculation.jsp",
#From Nikto for CF shiz
	"/cfappman/index.cfm", #susceptible to ODBC/pipe-style exploit; see RFP9901 http://www.wiretrip.net/rfp/p/doc.asp/i2/d3.htm
	"/cfdocs/dochome.htm",
	"/getFile.cfm",
	"/page.cfm",
	"/cfdocs/exampleapps/sorry.htm",
	"/cfdocs/examples/cvbeans/beaninfo.cfm", #susceptible to ODBC/pipe-style exploit; see RFP9901 http://www.wiretrip.net/rfp/p/doc.asp/i2/d3.htm
	"/cfdocs/examples/parks/detail.cfm", #susceptible to ODBC/pipe-style exploit; see RFP9901 http://www.wiretrip.net/rfp/p/doc.asp/i2/d3.htm
	"/cfdocs/expeval/openfile.cfm", #Can be used to expose the system/server path.
	"/cfdocs/cfmlsyntaxcheck.cfm", #Can be used for a DoS on the server by requesting it check all .exe's
	"/cgi/cfdocs/expeval/ExprCalc.cfm?", #The ColdFusion install allows attackers to read arbitrary files remotely ExprCalc.cfm?OpenFilePath=c:\winnt\win.ini
	"/cfdocs/expeval/exprcalc.cfm?", #The ColdFusion install allows attackers to read arbitrary files remotely ExprCalc.cfm?OpenFilePath=c:\winnt\win.ini
	"/cfdocs/exampleapp/email/getfile.cfm?", #Allows attacker to view arbitrary files getfile.cfm?filename=c:\boot.ini
	"/cfdocs/exampleapp/docs/sourcewindow.cfm?", #Allows attacker to view arbitrary files sourcewindow.cfm?Template=c:\boot.ini
	"/docs/showtemp.cfm?", #Gafware's CFXImage allows remote users to view any file on the system showtemp.cfm?TYPE=JPEG&FILE=c:\boot.ini
	"/cfdocs/expeval/displayopenedfile.cfm", #Unknown vuln...WTF
	"/cfdocs/expelval/openfile.cfm", 
	"/cfdocs/expeval/sendmail.cfm", #Can be used to send email
	"/cfdocs/snippets/fileexists.cfm", #Can be used to verify the existance of files (on the same drive info as the web tree/file)
	"/cfdocs/snippets/viewexample.cfm", #This can be used to view .cfm files, request viewexample.cfm?Tagname=..\..\..\file  (.cfm is assumed)
	"/cfdocs/snippets/evaluate.cfm", #Can enter CF code to be evaluated, or create denial of service see www.allaire.com/security/ technical papers and advisories for info
	"/cfide/Administrator/startstop.html", #Can start/stop server
	"/cfdocs/snippets/gettempdirectory.cfm", #depending on install, creates files, gives you physical drive info, sometimes defaults to \winnt\ directory as temp directory
	"/cfdocs/exampleapp/email/application.cfm", #Calls for further investigation
	"/cfdocs/exampleapp/publish/admin/addcontent.cfm", #Calls for further investigation
	"/cfdocs/exampleapp/publish/admin/application.cfm", #Calls for further investigation
	"/cfdocs/examples/httpclient/mainframeset.cfm", #Calls for further investigation
	]
	
	path2 = [
		"/CFIDE/wizards/common/_logintowizard.cfm",
		"/CFIDE/main/ide.cfm", #if 200 RDS is enabled
		"/_mmServerScripts/MMHTTPDB.php",
		]
	#AMF Injection strings
	path3 = [
		"/flex2gateway/",
		"/flex2gateway/http",  # ColdFusion 9 (disabled by default)
		"/flex2gateway/httpsecure", # ColdFusion 9 (disabled by default) SSL
		"/flex2gateway/cfamfpolling",
		"/flex2gateway/amf",
		"/flex2gateway/amfpolling",
		"/messagebroker/http",
		"/messagebroker/httpsecure", #SSL
		"/blazeds/messagebroker/http", # Blazeds 3.2
                "/blazeds/messagebroker/httpsecure", #SSL
                "/samples/messagebroker/http", # Blazeds 3.2
                "/samples/messagebroker/httpsecure", # Blazeds 3.2 SSL
		"/lcds/messagebroker/http", # LCDS 
                "/lcds/messagebroker/httpsecure", # LCDS -- SSL
                "/lcds-samples/messagebroker/http", # LCDS 
                "/lcds-samples/messagebroker/httpsecure", # LCDS -- SSL
		]
	#fuzzdb Coldfusion strings
	path4 = [
		"/CFIDE/Administrator/",
		"/CFIDE/Administrator/Application.cfm",
		"/CFIDE/Administrator/index.cfm",
		"/CFIDE/administrator/aboutcf.cfm",
		"/CFIDE/Administrator/checkfile.cfm",
		"/CFIDE/Administrator/enter.cfm",
		"/CFIDE/Administrator/header.cfm",
		"/CFIDE/Administrator/homefile.cfm",
		"/CFIDE/Administrator/homepage.cfm",
		"/CFIDE/Administrator/login.cfm",
		"/CFIDE/Administrator/logout.cfm",
		"/CFIDE/Administrator/navserver.cfm",
		"/CFIDE/Administrator/right.cfm",
		"/CFIDE/Administrator/tabs.cfm",
		"/CFIDE/Administrator/welcome.cfm",
		"/CFIDE/Administrator/welcomedoc.cfm",
		"/CFIDE/Administrator/welcomeexapps.cfm",
		"/CFIDE/Administrator/welcomefooter.cfm",
		"/CFIDE/Administrator/welcomegetstart.cfm",
		"/CFIDE/Application.cfm",
		"/CFIDE/adminapi/",
		"/CFIDE/adminapi/Application.cfm",
		"/CFIDE/adminapi/_datasource/",
		"/CFIDE/adminapi/_datasource/formatjdbcurl.cfm",	#path disclosure
		"/CFIDE/adminapi/_datasource/getaccessdefaultsfromregistry.cfm",	#path disclosure
		"/CFIDE/adminapi/_datasource/geturldefaults.cfm",	#path disclosure
		"/CFIDE/adminapi/_datasource/setdsn.cfm",	#path disclosure
		"/CFIDE/adminapi/_datasource/setmsaccessregistry.cfm",	#path disclosure
		"/CFIDE/adminapi/_datasource/setsldatasource.cfm",	#path disclosure
		"/CFIDE/adminapi/administrator.cfc",
		"/CFIDE/adminapi/base.cfc",
		"/CFIDE/adminapi/customtags/",
		"/CFIDE/adminapi/customtags/l10n.cfm", #path disclosure
		"/CFIDE/adminapi/customtags/resources",
		"/CFIDE/adminapi/customtags/resources/",
		"/CFIDE/adminapi/datasource.cfc",
		"/CFIDE/adminapi/debugging.cfc",
		"/CFIDE/adminapi/eventgateway.cfc",
		"/CFIDE/adminapi/extensions.cfc",
		"/CFIDE/adminapi/mail.cfc",
		"/CFIDE/adminapi/runtime.cfc",
		"/CFIDE/adminapi/security.cfc",
		"/CFIDE/classes/",
		"/CFIDE/classes/cf-j2re-win.cab",
		"/CFIDE/classes/cfapplets.jar",
		"/CFIDE/classes/images",
		"/CFIDE/componentutils/",
		"/CFIDE/componentutils/Application.cfm",
		"/CFIDE/componentutils/_component_cfcToHTML.cfm",
		"/CFIDE/componentutils/_component_cfcToMCDL.cfm?",
		"/CFIDE/componentutils/_component_style.cfm",
		"/CFIDE/componentutils/_component_utils.cfm",
		"/CFIDE/componentutils/cfcexplorer.cfc",
		"/CFIDE/componentutils/cfcexplorer_utils.cfm",
		"/CFIDE/componentutils/componentdetail.cfm",
		"/CFIDE/componentutils/componentdoc.cfm",
		"/CFIDE/componentutils/componentlist.cfm",
		"/CFIDE/componentutils/gatewaymenu",
		"/CFIDE/componentutils/gatewaymenu/",
		"/CFIDE/componentutils/gatewaymenu/menu.cfc",
		"/CFIDE/componentutils/gatewaymenu/menunode.cfc",
		"/CFIDE/componentutils/login.cfm",
		"/CFIDE/componentutils/packagelist.cfm",
		"/CFIDE/componentutils/utils.cfc",
		"/CFIDE/debug/",
		"/CFIDE/debug/images/",
		"/CFIDE/debug/includes/",
		"/CFIDE/debug/cf_debugFr.cfm", #path disclosure
		"/CFIDE/images/",
		"/CFIDE/images/skins/",
		"/CFIDE/install.cfm",
		"/CFIDE/installers/",
		"/CFIDE/installers/CFMX7DreamWeaverExtensions.mxp",
		"/CFIDE/installers/CFReportBuilderInstaller.exe",
		"/CFIDE/probe.cfm",
		"/CFIDE/scripts/",
		"/CFIDE/scripts/css/",
		"/CFIDE/scripts/xsl/",
		"/CFIDE/wizards/",
		"/CFIDE/wizards/common/",
		"/CFIDE/wizards/common/utils.cfc",
		"/cfappman/index.cfm",
		"/cfdocs/MOLE.CFM",
		"/cfdocs/TOXIC.CFM",
		"/cfdocs/cfmlsyntaxcheck.cfm",
		"/cfdocs/exampleapp/docs/sourcewindow.cfm",
		"/cfdocs/cfcache.map",
		"/cfdocs/exampleapp/email/getfile.cfm?filename=c:\\boot.ini",
		"/cfdocs/exampleapp/publish/admin/addcontent.cfm",
		"/cfdocs/examples/cvbeans/beaninfo.cfm",
		"/cfdocs/examples/parks/detail.cfm",
		"/cfdocs/expeval/displayopenedfile.cfm",
		"/cfdocs/expeval/eval.cfm",
		"/cfdocs/expeval/exprcalc.cfm",
		"/cfdocs/expeval/openfile.cfm",
		"/cfdocs/expeval/sendmail.cfm",
		"/cfdocs/expressions.cfm",
		"/cfdocs/root.cfm",
		"/cfdocs/snippets/evaluate.cfm",
		"/cfdocs/snippets/fileexists.cfm",
		"/cfdocs/snippets/gettempdirectory.cfm",
		"/cfdocs/snippets/viewexample.cfm",
		"/cfdocs/zero.cfm",
		"/cfusion/cfapps/forums/data/forums.mdb",
		"/cfusion/cfapps/forums/forums_.mdb",
		"/cfusion/cfapps/security/data/realm.mdb",
		"/cfusion/cfapps/security/realm_.mdb",
		"/cfusion/database/cfexamples.mdb",
		"/cfusion/database/cfsnippets.mdb",
		"/cfusion/database/cypress.mdb",
		"/cfusion/database/smpolicy.mdb",
		]
		
		path.each do | check |
			res = send_request_raw({
				'uri'     => check,
				'method'  => 'GET',
			}, 25)
			
			if (res.nil?)
				print_error("no response for #{ip}:#{rport} #{check}")
			elsif (res.code == 200 or res.code == 500)
				print_good("#{rhost}:#{rport} #{check} #{res.code}")
						report_note(
							:host	=> ip,
							:proto	=> 'tcp',
							:port   	=> rport,
							:sname	=>  'HTTP',
							:type	=> 'coldfusion.url',
							:data	=> "#{check} Code:#{res.code}",
							:update => :unique_data
							)
			elsif (res.code == 302 or res.code == 301)
				print_status("#{res.code} Redirect to->#{res.headers['Location']}")
			elsif (res.code == 401)
				print_status("#{res.code} Authentication Required for #{check}")
						report_note(
							:host	=> ip,
							:proto	=> 'tcp',
							:port   	=> rport,
							:sname	=>  'HTTP',
							:type	=> 'coldfusion.url',
							:data	=> "#{check} Code:#{res.code}",
							:update => :unique_data
							)
			else
				vprint_error("#{res.code} for #{check}")
			end
		end

		path2.each do | check |
			res = send_request_cgi({
				'uri'     => check,
				'method'  => 'POST',
			}, 25)
			
			if (res.nil?)
				print_error("no response for #{ip}:#{rport} #{check}")
			elsif (res.code == 200 or res.code == 500)
				print_good("#{rhost}:#{rport} #{check} #{res.code}")
					report_note(
							:host	=> ip,
							:proto	=> 'tcp',
							:port   	=> rport,
							:sname	=>  'HTTP',
							:type	=> 'coldfusion.url',
							:data	=> "#{check} Code:#{res.code}",
							:update => :unique_data
							)
			elsif (res.code == 302 or res.code == 301)
				print_status("#{res.code} Redirect to->#{res.headers['Location']}")
			elsif (res.code == 401)
				print_status("#{res.code} Authentication Required for #{check}")
			else
				vprint_error("#{res.code} for #{check}")
			end
		end

		path3.each do | check |
			res = send_request_cgi({
				'uri'     => check,
				'method'  => 'POST',
				'version'      => '1.1',
				'Content-type' => 'application/x-amf',
			}, 25)
			
			if (res.nil?)
				print_error("no response for #{ip}:#{rport} #{check}")
			elsif (res.code == 200 or res.code == 500)
				print_good("#{rhost}:#{rport} #{check} #{res.code}")
					report_note(
							:host	=> ip,
							:proto	=> 'tcp',
							:port   	=> rport,
							:sname	=>  'HTTP',
							:type	=> 'coldfusion.url',
							:data	=> "#{check} Code:#{res.code}",
							:update => :unique_data
							)
			elsif (res.code == 302 or res.code == 301)
				print_status("#{res.code} Redirect to->#{res.headers['Location']}")
			elsif (res.code == 401)
				print_status("#{res.code} Authentication Required for #{check}")
			else
				vprint_error("#{res.code} for #{check}")
			end
		end
		
		path4.each do | check |
			res = send_request_raw({
				'uri'     => check,
				'method'  => 'GET',
			}, 25)
			
			if (res.nil?)
				print_error("no response for #{ip}:#{rport} #{check}")
			elsif (res.code == 200 or res.code == 500)
				print_good("#{rhost}:#{rport} #{check} #{res.code}")
					report_note(
							:host	=> ip,
							:proto	=> 'tcp',
							:port   	=> rport,
							:sname	=>  'HTTP',
							:type	=> 'coldfusion.url',
							:data	=> "#{check} Code:#{res.code}",
							:update => :unique_data
							)
			elsif (res.code == 302 or res.code == 301)
				print_status("#{res.code} Redirect to->#{res.headers['Location']}")
			elsif (res.code == 401)
				print_status("#{res.code} Authentication Required for #{check}")
			else
				vprint_error("#{res.code} for #{check}")
			end
		end
		
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end

#/CFIDE/wizards/common/utils.cfc?method=wizardhash&returnformat=json&inpassword=foo
#/CFIDE/componentutils/cfcexplorer.cfc?method=getcfcinhtml&name=CFIDE.wizards.common.utils&path=/CFIDE/wizards/common/utils.cfc
