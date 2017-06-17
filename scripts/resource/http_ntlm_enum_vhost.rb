<ruby>

#variables
maxjobs = 5		#throttling if we get too much jobs

#default to 15 Threads
if (framework.datastore['THREADS'] == nil)
    run_single("setg THREADS 1")
end

run_single("setg VERBOSE TRUE")

if (framework.datastore['VERBOSE'] == "true")	#we look in the global datastore for a global VERBOSE option and use it
    verbose = 1 #true
    else
    verbose = 0
end

# Test and see if we have a database connected
begin
    framework.db.hosts
    rescue ::ActiveRecord::ConnectionNotEstablished
    print_error("Database connection isn't established")
    return
end

def jobwaiting(maxjobs,verbose)	#thread handling for poor guys
    while(framework.jobs.keys.length >= maxjobs)
        ::IO.select(nil, nil, nil, 2.5)
        if(verbose == 1)
            print_error("WAITING for finishing some modules... active jobs: #{framework.jobs.keys.length} / threads: #{framework.threads.length}")
        end
    end
end

#this part should be used to populate the DB with open ports/services

File.open("/Users/path/to/domain-ntlm.txt", "r") do |f|
    f.each_line do |line|
        run_single("setg RHOSTS #{line}")
        run_single("setg VHOST #{line}")
        print_line("")
        
        print_line("")
        print_line("Looking for web servers")
        print_line("")
        print_line("Module: HTTP NTLM ENUM")
        run_single("use auxiliary/scanner/http/ntlm_info_enumeration")
        run_single("set RPORT 443")
        run_single("set SSL TRUE")
        run_single("run -j")
        run_single("back")
        jobwaiting(maxjobs,verbose)

    end
end
</ruby>
