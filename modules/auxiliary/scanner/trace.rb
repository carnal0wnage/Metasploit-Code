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
	#include Msf::Auxiliary::WMAPScanServer
	# Scanner mixin should be near last
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'HTTP TRACE Detection',
			'Version'     => '$Revision:use$',
			'Description' => 'Test TRACE Methods',
			'Author'       => ['CG'],
			'License'     => MSF_LICENSE
		)
		
	end

	def run_host(target_host)

		begin
			res = send_request_raw({
				'version'      => '1.0',
				'uri'          => '/',					
				'method'       => 'TRACE'
			}, 10)


			if (res and res.code >= 200)
				statuscode = res.code
				#print statuscode #debug
				response = case res.code
 					when 200 then "TRACE is **probably** enabled -- We received a 200 Response"
 					when 301 then "Site is responding with a 301 - Redirect for \"/\""
					when 302 then "Site is responding with a 302 - Redirect for \"/\""
 					when 403 then "TRACE is disabled. 403 Forbidden"
 					when 404 then "TRACE is probably disabled. 404 Not Found"
 					when 405 then "TRACE is disabled. 405 Method Not Allowed Response"
					when 500 then "TRACE is probably disabled. 500 Method Not Allowed Response"
 					when 501 then "TRACE is disabled. 501 Not Implemented Response"
 					else "Unexpected Response."
					end
			else
				''
			end
			
			print_status("#{response} for #{target_host}")
				
				

				report_note(
				:host	=> target_host,
				:proto	=> 'HTTP',
				:port	=> rport,
				:type	=> 'TRACE Response Code',
				:data	=> "#{response} for #{target_host}"
			)

				
		end
			
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
#end

