##
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##


require 'msf/core'


class Metasploit3 < Msf::Auxiliary
	
	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize
		super(
			'Name'        => 'Coldfusion RDS Check',
			'Version'     => '$Revision:$',
			'Description' => 'Checks to see if RDS is enabled, if so attempts to determine coldfusion version',
			'Author'       => ['CG'],
			'License'     => MSF_LICENSE
		)
		
		register_options(
	                        [
	                                OptString.new('PATH', [ true,  "The path to identify files", '/']), 
					OptString.new('User-Agent', [ true, "The HTTP User-Agent sent in the request", 'Mozilla/3.0 (compatible; Macromedia RDS Client)' ]),
				], self.class)
	end

	def run_host(target_host)
		
		tpath = "/CFIDE/main/ide.cfm?CFSRV=IDE&ACTION=IDE_DEFAULT" 
		postrequest = "4:STR:14:ConfigurationsSTR:10:7, 0, 0, 0STR:0:STR:18:4411433f371d434005" #no username & password of password1

		begin
			res = send_request_cgi({
                               'uri'          =>  tpath,
                               'method'       => 'POST',
                               'agent'        => datastore['User-Agent'],
                               'connection'   => 'close, TE',
                               'data'             =>  postrequest,
                               'headers'      =>  	{
							'TE' => "trailers, deflate, gzip, compress",
								},
                       }, 10)
			
			if (res.nil?)
				print_error("No response for #{rhost}:#{rport}#{tpath}")
			elsif (res.code == 200)
				 match = res.body.match(/ColdFusion Server Version:.(.*):.*ColdFusion Client Version:.(.*):\d*:*/);
					server = $1
					client  = $2
					if (client.nil? or server.nil?)
						vprint_error("Received a 200 for the requst but no ColdFusion version information was present")
					else
						print_good("#{rhost}:#{rport} RDS appears to be enabled at http://#{rhost}:#{rport}/CFIDE/main/ide.cfm")
						print_good("#{rhost}:#{rport} ColdFusion Server Version: " + $1 + " ColdFusion Client Version: " + $2 + "\r\n")
					end
					report_note(
						:host	=> target_host,
						:proto	=> 'tcp',
						:port		=>  rport,
						:sname    =>  (ssl ? 'https' : 'http'),
						:type	=> 'coldfusion.server.version',
						:data	=> "ColdFusion Server Version:#{server} ColdFusion Client Version:#{client}"
							)
			elsif (res.code == 500)
				vprint_status("Received a #{res.code} RDS is probably not enabled on #{rhost}")
			elsif (res.code == 400 or res.code == 404)
				vprint_status("Received a #{res.code} RDS is probably not enabled on #{rhost}")
			elsif (res.code == 302)
				vprint_status("Received a #{res.code} 302 Redirect to #{res.headers['Location']}")
			else
				vprint_status("Recevied: #{res.code}")
			end
		end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH =>e
	end
end

	#string we are regexing: 4:4:-50037:ColdFusion Server Version: 6, 0, 0, 037:ColdFusion Client Version: 4, 0, 0, 00:
	#string we are regexing: 5:4:-50037:ColdFusion Server Version: 8, 0, 0, 037:ColdFusion Client Version: 7, 0, 0, 01:11:0