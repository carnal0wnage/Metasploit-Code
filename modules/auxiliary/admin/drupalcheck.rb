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
			'Name'        	=> 'Drupal Check',
			'Version'     	=> '$Revision: $',
			'Description'	=> 'This module check for the existence of the Drupal CMS by using the Expires: Sun, 19 Nov 1978 05:00:00 GMT header value.  This should identify Drupal 4.6 and above.  You MUST set the VHOST to be the domain name for this to work.',
			'Author'        => ['CG'],
			'License'	=> MSF_LICENSE,
			'References'	=>
				[
					[ 'URL', 'http://www.lullabot.com/articles/is-site-running-drupal' ],
				]
		)
	
		register_options(
			[
				OptString.new('UserAgent', [true, "The HTTP User-Agent sent in the request", 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
				OptString.new('VHOST', [true, "The VHOST -- Must set for this module", 'www.google.com' ])
			], self.class)
end

	def run
		

		begin
			agent = datastore['UserAgent']
			res = send_request_raw({
				'version'	=> '1.0',
				'uri'		=>  '/',					
				'method'        => 'GET',
				'headers'       =>
	                       	{
					'Accept'        => '*/*',
					'Connection'    => 'Keep-Alive',
				}	                        

			}, 10)
			
			if (res and res.headers['Expires'])
				if res.headers['Expires'] =~ /Sun, 19 Nov 1978 05:00:00 GMT/
					print_status("#{datastore['RHOST']} is running Drupal CMS\nServer response #{res.headers['Expires']}")
				elsif 
					print_status("#{datastore['RHOST']} is not running Drupal CMS\nServer response #{res.headers['Expires']}")
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

