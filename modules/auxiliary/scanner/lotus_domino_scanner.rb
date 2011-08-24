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
			'Name'        => 'Lotus Domino Scanner',
			'Version'     => '$Revision$',
			'Description' => %q{
				This module scans for common Lotus Domino Base URLs.
			},
			'References'  =>
			[
				[ 'URL', 'http://carnal0wnage.attackresearch.com' ],
			],
			'Author'      => [ 'CG' ],
			'License'     => MSF_LICENSE
			)

			register_options(
				[
			OptString.new('BASEFILE', [ true, 'The file that contains a list of base urls.', File.join(Msf::Config.install_root, 'data', 'wordlists', 'lotus_domino_bases.txt')]),
				], self.class)
	
	end

	def run_host(ip)
			noauth = []
			auth = []
			forward = []
			print_status ("Scanning #{ip}:#{rport}")

			blah = File.open(datastore['BASEFILE'])
			blah.each do | check |
			res = send_request_raw({
				'uri'     => "/"+check.chomp,
				'method'  => 'GET',
				'version'  => '1.1'
			}, 10)

				if (res.nil?)
					print_error("no response for #{ip}:#{rport} #{check}")
				elsif (res.code == 200 )
					#print_status("#{res.code}:#{check.chomp}")
					if (res.body =~ /names.nsf\?Login/ or res.body =~ /NAMES.nsf\?Login/)
						auth << check+"\n"
					else
						noauth << check+"\n"
					end
				elsif (res.code == 302 or res.code == 403 or res.code == 401)
					#print_status("#{res.code}:#{check.chomp}")
					forward << check+"\n"
				elsif (res.code == 404 or res.code == 500)
					#print_status("#{res.code}:#{check.chomp}")
				else
					''
					#print_status("#{res.code}:#{check.chomp}")
				end
			#end
			end
				print_status("Bases with Anonymous Access: ")
				noauth.each { |x| print("#{x.chomp}") }
				puts ''
				print_status("Bases Requiring Authentication: ")
				auth.each { |x| print("#{x.chomp}") }
				puts ''
				print_status("Forward: ")
				forward.each { |x| print("#{x.chomp}") }
				puts ''
		

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
		rescue ::Timeout::Error, ::Errno::EPIPE
		end
	end
