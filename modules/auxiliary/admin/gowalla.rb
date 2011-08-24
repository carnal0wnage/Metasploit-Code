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
			'Name'        	=> 'Gowalla Location Poster',
			'Version'     	=> '$Revision:$',
			'Description'	=> 'Fuck with Gowalla, be anywhere you want to be by spot id',
			'Author'        => ['CG'],
			'License'	=> MSF_LICENSE,
			'References'	=>
				[
					[ 'URL', 'http://groups.google.com/group/foursquare-api' ],
					[ 'URL', 'http://www.mikekey.com/im-a-foursquare-cheater/'],
				]
		)
#todo pass in geocoords instead of venueid, create a venueid, other tom foolery
		register_options(
			[
				Opt::RHOST('api.gowalla.com'),
				OptString.new('UserAgent', [true, "Specify Gowalla UserAgent",'Gowalla/1.1 (unknown, Android, 4, android, 0.9.1, 320x480)']),
				#OptString.new('UserAgent', [true, "Specify Gowalla UserAgent",'Gowalla/1.1 (unknown, Android, 4, android-devphone1/Android Dev Phone 1, 0.9.1-73-g59c95ca, 320x480)']),
				OptString.new('SPOTID', [ true, 'gowalla spot id', '14515']), #Facebook HQ
				OptString.new('USERNAME', [ true, 'gowalla username', 'username']),
				OptString.new('PASSWORD', [ true, 'gowalla password', 'password']),
				OptString.new('GPSLONGITUDE', [ true, 'GPS Longitude', '-122.1525514126']),
				OptString.new('GPSLATITUDE', [ true, 'GPS Latitude', '37.4157602871']),
				OptString.new('GOWALLAAPIKEY', [ true, 'gowalla API Key', '4a35a8b7df6a405a816b01cd5b44b95d']),
				OptString.new('COMMENT', [ true, 'Comment', 'fooooood']),
			], self.class)
	
	end

	def run
	
		begin
			user = datastore['USERNAME']
			pass = datastore['PASSWORD']
			spotid = datastore['SPOTID']
			lng = datastore['GPSLONGITUDE']
			lat = datastore['GPSLATITUDE']
			api = datastore['GOWALLAAPIKEY']
			comment = datastore['COMMENT']

			user_pass = Rex::Text.encode_base64(user + ":" + pass)
			decode = Rex::Text.decode_base64(user_pass)
			postrequest = "lng=#{lng}&accuracy=0.0&post_to_facebook=0&post_to_twitter=1&comment=#{comment}&lat=#{lat}\n"

			print_status("Base64 Encoded User/Pass: #{user_pass}") #debug
			print_status("Base64 Decoded User/Pass: #{decode}") #debug

			res = send_request_cgi({
				'uri'     => "/checkins?spot_id=#{spotid}",
				'version'	=> "1.1",
				'method'  => 'POST',
				'data'   => postrequest,
				'headers' =>
					{
						'Authorization' => "Basic #{user_pass}",
						'X-Gowalla-API-Version' => "1",
						'Accept' => 'application/json',
						'Proxy-Connection' =>  "Keep-Alive",
						'X-Gowalla-API-Key' => "#{api}"
					}
			}, 25)
			
			print_status("#{res}") #this outputs entire response, could probably do without this but its nice to see whats going on
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE =>e
			puts e.message
	end
end


