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
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Oracle Application Server Detection',
			'Version'     => '$Revision:  $',
			'Description' => 'Checks the server headers for common Oracle Application Server (PL/SQL Gateway) Headers.  You may want to set the URIPATH to /apex/ as a check for Oracle Application Express Servers.',
			'Author'      => 'CG' ,
			'License'     => MSF_LICENSE,
			'References'	=>
				[
					[ 'URL', 'http://www.owasp.org/index.php/Testing_for_Oracle' ]
				]
		)
		register_options(
			[
				OptString.new('URIPATH', [ true,  "The URI PATH", '/'])
			], self.class)
	end

	def run_host(ip)

		begin	
			path = datastore['URIPATH']
			res = send_request_raw({
				'uri'          => path, 
#Oracle Application Express only say oracle with /apex/ request/"most" other boxes will still reply with Oracle in Server Headers for 404
				'method'       => 'GET'
						}, 10)

			if (res and res.headers['Server'])
				if res.headers['Server'] =~ /Oracle/ or res.headers['Server'] =~ /Oracle HTTP Server/ or res.headers['Server'] =~ /Oracle-Application-Server/ or res.headers['Server'] =~ /Oracle_Web_Listener/ or res.headers['Server'] =~ /Oracle9iAS/ or res.headers['Server'] =~ /mod_plsql/ or res.headers['Server'] =~ /Oracle XML DB/ or res.headers['Server'] =~ /Apache\/1.3.12 \(Win32\) ApacheJServ\/1.1 mod_ssl\/2.6.4 OpenSSL\/0.9.5a mod_perl\/1.22/
					print_status("Oracle Application Server Found!")
					print_status("#{ip} is running #{res.headers['Server']}")
						report_note(
							:host	=> ip,
							:proto	=> 'HTTP',
							:port	=> rport,
							:type	=> 'ORACLE_APPLICATION_SERVER',
							:data	=> "#{res.headers['Server']}"
							)

				else
					print_status("#{rhost}:#{rport}") #debug
					print_status("#{res.headers}") #debug
					#''
				end

			end
		
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end

	end
	
end

#Oracle 8.1.7 
#Server: Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a mod_perl/1.22

#Oracle Application Server Forms and Reports Services 10.1.2.0.2
#Server: Oracle-Application-Server-10g/10.1.2.0.2 Oracle-HTTP-Server OracleAS-Web-Cache-10g/10.1.2.0.2 (G;max-age=0+0;age=0;ecid=3285557964107,0)

#Oracle Database 9i
#Server: Oracle HTTP Server Powered by Apache/1.3.22 (Win32) mod_plsql/3.0.9.8.3b mod_ssl/2.8.5 OpenSSL/0.9.6b mod_fastcgi/2.2.12 mod_oprocmgr/1.0 mod_perl/1.25

#Oracle App Server 10.1.2.0
#Server: Oracle-Application-Server-10g/10.1.2.0.0 Oracle-HTTP-Server OracleAS-Web-Cache-10g/10.1.2.0.0 (G;max-age=0+0;age=0;ecid=3710918334042,0)



