##
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
              'Name'        => 'Cisco ASA Version Leak',
              'Version'     => '',
              'Description' => 'Check if cisco ASA is leaking version info',
              'Author'       => ['CG'],
              'License'     => MSF_LICENSE,
              'References'	=>
              [
                    [ 'CVE', '2014-3398'],
                    [ 'URL', 'https://ruxcon.org.au/assets/2014/slides/Breaking%20Bricks%20Ruxcon%202014.pdf' ],
              ]
          )

              register_options(
                    [
                      Opt::RPORT(443),
                      OptBool.new('SSL', [true, "Negotiate SSL for outgoing connections", true]),
                    ], self.class
              )
    end

  def run_host(target_host)

    begin

      res = send_request_cgi({
          'version'      => '1.0',
          'uri'          => "/CSCOSSLC/config-auth",
          'method'       => 'GET',
      }, 10)

      if res.nil?
        print_error("no repsonse for #{target_host}")
      elsif (res.code == 200)
        if (res.body =~ /<version who="sg">(.*?)<\/version>/im )
          blah = $1
          print_good("#{target_host}:#{rport}-ASA Version: #{blah}")
          report_note(
                      :host        => target_host,
                      :proto       => 'tcp',
                      :type        => 'CISCO ASA VERSION',
                      :data        => "#{blah}",
                      :port        => "#{rport}",
                      :ssl         => ssl,
          )

        else
          print_error("Received 200 but no match on ASA version")
        end
      elsif (res.code == 301 or res.code == 302)
          print_status("#{target_host}:#{rport} Received 302 to #{res.headers['Location']} (PATCHED)")
      elsif (res.code == 404)
          vprint_status("#{target_host}:#{rport} -- #{res.code}")
      else
          vprint_status("#{target_host}:#{rport} -- #{res.code}\n#{res.body}")
      end

        rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
        rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end

#8.2(5.48), 8.3(2.40), 8.4(7.15), 8.6(1.13), 8.7(1.11), 9.0(4.1), or 9.1(4.5). Fixed to CVE-2014-2127
