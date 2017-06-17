<ruby>

#variables
maxjobs = 1		#throttling if we get too much jobs

#default to 15 Threads
if (framework.datastore['THREADS'] == nil)
	run_single("setg THREADS 15")
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

File.open("/path/to/subdomains/domains-list.txt", "r") do |f|
    f.each_line do |line|
        print_line("")
        print_line("ZT ATTEMPTS")
        print_line("")
        print_line("Module: DNS GATHER")
        run_single("use auxiliary/gather/enum_dns")
        run_single("set DOMAIN #{line}")
        run_single("run -j")
        jobwaiting(maxjobs,verbose)
    end
end
</ruby>
