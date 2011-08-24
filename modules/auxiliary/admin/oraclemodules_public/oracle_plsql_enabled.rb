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
			'Description' => 'Checks to see if PL/SQL is enabled. If the server responds with a 200 OK response for the first request ("null") and a 404 Not Found for the second (something random) then it indicates that the server is running the PL/SQL Gateway. Pay careful attention to the /\'s
			 in URIPATH and DAD',
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
				OptString.new('DAD', [ true,  "The Database Access Descriptor", 'portal/'])
			], self.class)
	end

	def run

		check1 = "null"
		check2 = Rex::Text.rand_text_alpha_upper(rand(10) + 1)
		 
		nullcheck = ''
		nonnullcheck = ''

		begin	
			path = datastore['URIPATH']
			dad = datastore['DAD']
			
			print_status("Sending requests to #{rhost}:#{rport}#{path}#{dad}\n")
			
			res = send_request_raw({
				'uri'          => path + dad + check1, 
				'method'       => 'GET'
						}, 10)

			if (res.nil?)
				print_error("No response for #{rhost}:#{rport} #{check1}")
			elsif (res and res.code == 200)
				print_status("Received #{res.code} for #{check1}")
				nullcheck << res.code.to_s
			elsif(res.code == 302 or res.code == 301)
				print_status("Redirect to #{res.headers['Location']}")
				nullcheck << res.code.to_s
			else
				print_status("Received #{res.code} for #{check1}")
				nullcheck << res.code.to_s
				#''
			end

			res = send_request_raw({
				'uri'          => path + dad + check2, 
				'method'       => 'GET'
						}, 10)

			if (res.nil?)
				print_error("No response for #{rhost}:#{rport} #{check2}")
			elsif (res and res.code == 200)
				print_status("Received #{res.code} for #{check2}")
				nonnullcheck << res.code.to_s
			elsif(res.code == 302 or res.code == 301)
				print_status("Redirect to #{res.headers['Location']}")
				nonnullcheck << res.code.to_s
			else
				print_status("Received #{res.code} for #{check2}")
				nonnullcheck << res.code.to_s
					#''
			end
			
			#need to do the null/nonnull shiz here to say if pl/sql is enabled or not
			if (nullcheck == "200" and nonnullcheck == "404")
				print_good("#{rhost}:#{rport}#{path}#{dad} PL/SQL Gateway appears to be running!")
			else
				print_error("PL/SQL gateway is not running")
			end
		end	
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
	end	
end
