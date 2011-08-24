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
			'Name'        => 'HTTP Index Page grabber',
			'Version'     => '$Revision:$',
			'Description' => %q{
				Scans a range and grabs the content of a GET request and outputs it to file.
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
						Opt::RPORT(80),
						OptString.new('URL', [ true,  "URI Path", '/']),
						OptString.new('UserAgent', [ true, "The HTTP User-Agent sent in the request", 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ]),
					], self.class)
	end

	def run_host(ip)

		url = datastore['URL']
		host = ip
		
		# Create Filename info to be appended to downloaded files
		filenameinfo = "_" + ::Time.now.strftime("%Y%m%d.%M%S")
		
		# Create a directory for the logs
		logs = ::File.join(Msf::Config.log_directory, 'auxiliary', 'http_index_grabber')

		# Create the log directory
		::FileUtils.mkdir_p(logs)

		#logfile name
		logfile = logs + ::File::Separator + host + filenameinfo + ".html"

			res = send_request_raw({
					'uri'     => url,
					'method'  => 'GET',
					'versions' => '1.0',
						}, 15)

				if (res.nil?)
					print_error("no response for #{ip}:#{rport} #{url}")

				elsif (res.code == 200)
					
					extra = http_fingerprint(res)

					print_good("Received a HTTP 200 with #{res.headers['Content-Length']} bytes....Logging to file: #{logfile}")
					#print_good("Extras: #{extra}")
					exists = File.new(logfile,"a")
					exists.write "#{res.body}"
					exists.close
					if (extra.nil?)
						return ''
					else
						print_good("Extras: #{extra}")
					end
				elsif (res.code == 302 or res.code == 301)
					print_status("Received #{res.code} to #{res.headers['Location']} for #{ip}:#{rport}#{url}")
				else
					#''
					print_error("Received #{res.code} for #{ip}:#{rport}#{url}")	
				end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::ArgumentError
		rescue ::Timeout::Error, ::Errno::EPIPE
		end

	def http_fingerprint(res)
		return if not res

			extras = []
	
			case res.body
				when nil
					# Nothing
				when /openAboutWindow.*\>DD\-WRT ([^\<]+)\</
					extras << "DD-WRT #{$1.strip}"
				when /It works!/i
					extras << "Apache Default 'It Works!' Page"
				when /Microsoft Outlook Web Access/
					extras << "Microsoft OWA Login Page"
				when /Microsoft Office Outlook Web Access/
					extras << "Microsoft OWA Login Page"
				when /The site you are trying to view does not currently have a default page/
					extras << "Microsoft Default Under Construction Page"
				when /Under Construction/i
					extras << "Microsoft Default Under Construction Page"
				when /Cisco CallManager User Options Log On/i
					extras << "Cisco Call Manger Login"
				when /ID_ESX_Welcome/
					extras << "VMware ESX Server"
				when /Test Page for.*Fedora/
					extras << "Fedora Default Page"
				when /Placeholder page/
					extras << "Debian Default Page"
				when /Welcome to Windows Small Business Server (\d+)/
					extras << "Windows SBS #{$1}"
				when /Asterisk@Home/
					extras << "Asterisk"
				when /swfs\/Shell\.html/
					extras << "BPS-1000"
				when /axis .* network Camera/i
					extras << "Axis Network Camera Web Interface"
				when /Novell ZENworks Control Center/i
					extras << "Novell ZENworks Control Center Login"
			end
	end
end
