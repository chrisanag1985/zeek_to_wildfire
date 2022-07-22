@load base/frameworks/files
@load base/files/hash
@load base/frameworks/notice
@load base/utils/active-http
@load base/utils/patterns

module WildFireSandbox;


export {

       global WildFireSandbox::recheck_hash: event(f: fa_file);
       redef ActiveHTTP::default_method = "POST" ;
       redef enum Notice::Type += {
               Match,Info
       };

       # Interval - after will retry to get verdict for Pending Hashes or File Sumbits
       option API_KEY = "<API-KEY>" ;
       option WILDFIRE_SERVER = "http(s)://<ip or hostname>";
       option VERIFY_TLS = T;

      
       const sleep_interval = 30sec &redef ;
       const max_count = 10 &redef ;
       const get_verdict = "/publicapi/get/verdict" &redef;
       const submit_file = "/publicapi/submit/file" &redef;

      # check application/vnd.ms-cab-compressed
       option match_file_types = /application\/x-dosexec/ |
                               /application\/pdf/ |  
                               /application\/msword/ |
                               /application\/x-rar/ |
                               /application\/x-gzip/ |
		        	/application\/vnd.openxmlformats-officedocument/|
                               /application\/vnd.openxmlformats-officedocument.wordprocessingml.document/ |
                               /application\/vnd.openxmlformats-officedocument.spreadsheetml.sheet/ |
                               /application\/vnd.openxmlformats-officedocument.presentationml.presentation/ ;

}
# end of export



const verdict_to_notify: set[string]  = {"1","2","3","4","5"};
const verdictDict: table[string] of string = {
       ["0"]= "Benign",
       ["1"]= "Malware",
       ["2"]= "Grayware",
       ["4"]= "Phishing",
       ["5"]= "C2",
       ["-100"]= "Pending, the sample exists, but there is currently no verdict",
       ["-101"]= "Error",
       ["-102"]= "Unknown, cannot find sample record in the database",
       ["-103"]= "Invalid hash value"
 };
 
 
const wildfire_errors: table[count] of string = {

	[200]= "OK",
	[401]= "Invalid API key",
	[403]= "Forbidden",
	[404]= "Not Found",
	[405]= "Unsupported Method",
	[413]= "Request Entity Too Large",
	[418]= "Unsupported File Type",
	[419]= "Max Request Reached",
	[420]= "Insufficient Arguments",
	[421]= "Invalid Argument",
	[422]= "Unprocessable Entities",
	[500]= "Internal Error Internal error.",
	[513]= "File upload failed.",
};

 
 
# this contains sha256+uids as key and how many recheck requests has done so far
global hashes_monitor: table[string] of count;

function send_notice(verdict: string,f: fa_file){


               #print("Send Notice");
	       local uid = join_string_set(f$info$conn_uids,"");
	       local src:  addr ;
	       for ( s in f$info$tx_hosts ){
		
			src = s;
		}
	       local dst:  addr ;
	       for ( s in f$info$rx_hosts ){
		
			dst= s;
		}
	       local protocol = f$source;
               local n: Notice::Info = Notice::Info($note=Match,$uid=uid,$src=src,$dst=dst,$fuid=f$info$fuid,$msg=fmt("%s Detected",verdictDict[verdict]),$sub=fmt("Malicious file with SHA256: %s over %s with format %s  ",f$info$sha256,protocol,f$info$mime_type));

               NOTICE(n);




}




function send_hash_to_wildfire(f: fa_file): string{

       local hash = f$info$sha256;
       local form_data = " -F 'apikey="+API_KEY+"' -F 'hash="+hash+"'";
	   if (VERIFY_TLS){
			form_data = " -k "+form_data;
	   }
       local url = WILDFIRE_SERVER+get_verdict;
       local req = ActiveHTTP::Request($url=url,$addl_curl_args=form_data);


       @if (Version::number >= 50000)
	
           return  when [ req ](local response = ActiveHTTP::request($req=req))
	{
               if ( response?$code && response$code == 200){
                       local body = response$body;
                       local verdict = match_pattern(body,/<verdict>([-]?[0-9]{1,3})<\/verdict>/);
                       local verdict_str = verdict$str[9:-10];
                       return (verdict_str);
               }
	}
       @else
	
           return when (local response = ActiveHTTP::request($req=req))
	{


               if ( response?$code && response$code == 200){
                       local body = response$body;
                       local verdict = match_pattern(body,/<verdict>([-]?[0-9]{1,3})<\/verdict>/);
                       local verdict_str = verdict$str[9:-10];
                       return (verdict_str);
               }


	}
       @endif

}


function send_file_to_wildfire(f: fa_file) {

       local hash = f$info$sha256;
       #print(fmt("Send file %s",hash));
       local form_data = " -F 'apikey="+API_KEY+"' -F 'file=@./extract_files/"+hash+"'";
	   if (VERIFY_TLS){
			form_data = " -k "+form_data;
	   }
       local url = WILDFIRE_SERVER+submit_file;
       local req = ActiveHTTP::Request($url=url,$addl_curl_args=form_data);

       @if (Version::number >= 50000)
           when [ req,f ](local response = ActiveHTTP::request($req=req))
		{

               	if (response$code != 200){
                       print(response$code);
               	    }
		else {

                	schedule sleep_interval { WildFireSandbox::recheck_hash(f)};
		}
		}
       @else
           when (local response = ActiveHTTP::request($req=req))
		{
	
               	if (response$code != 200){
                       print(response$code);
               		}
		else {

                	schedule sleep_interval { WildFireSandbox::recheck_hash(f)};
		}
		}
       @endif
       
      
       
}

function do_verdict(verdict: string,f: fa_file){
    


	local uid = join_string_set(f$info$conn_uids,"");
	local hash = f$info$sha256;
	local id = hash+uid;
	local counter: count = hashes_monitor[id];

	#print(fmt("Counter %s Verdict: %s, Hash: %s",counter,verdict,hash));
        if (verdict in verdict_to_notify){
        
            send_notice(verdict,f);
        }

	if ( verdict != "-102" && verdict != "-100" ){

		delete hashes_monitor[id];
	}
        
        if (verdict == "-100"){
                #print(verdictDict[verdict]);
		if ( counter < max_count ){
			hashes_monitor[id] = counter+1;
                	schedule sleep_interval { WildFireSandbox::recheck_hash(f)};
		}else{
		
			print("More than max_count. stopping");
			delete hashes_monitor[id];
		        local src:  addr ;
		        for ( s in f$info$tx_hosts ){
		         
		         	src = s;
		         }
		        local dst:  addr ;
		        for ( s in f$info$rx_hosts ){
		         
		         	dst= s;
		         }
		        local protocol = f$source;
               		local n: Notice::Info = Notice::Info($note=Info,$uid=uid,$src=src,$dst=dst,$fuid=f$info$fuid,$msg=fmt("File Hash Exceeded the MAX Recheck tries"),$sub=fmt("File Hash: %s",f$info$sha256));

               		NOTICE(n);
		
        
        		}
	}
        if (verdict == "-102" && counter == 0){
		hashes_monitor[id] = counter+1;
                send_file_to_wildfire(f);

               }

}



event WildFireSandbox::recheck_hash(f: fa_file){
       #print(fmt("recheck %s counter: %s",f$info$sha256,hashes_monitor[f$info$sha256]));
       @if (Version::number >= 50000)
	
           when [f] (local verdict = send_hash_to_wildfire(f))
		{
               		do_verdict(verdict,f);
		}	
       @else
	
           when (local verdict = send_hash_to_wildfire(f))
	    {
               		do_verdict(verdict,f);
	    }
       @endif
}



event file_state_remove(f: fa_file){

       if ( !f$info?$extracted || !f$info?$sha256  )
               return;

       local orig = f$info$extracted;
       #print(orig);

       local split_orig = split_string(f$info$extracted, /\./);
       local extension = split_orig[|split_orig|-1];

       local dest = fmt("%s", f$info$sha256);

       # rename to SHA256 to stored files
       local cmd = fmt("mv ./extract_files/%s ./extract_files/%s", orig, dest);


       @if (Version::number >= 50000)
            when [cmd]( local result = Exec::run([$cmd=cmd]) )
		{}
       @else
            when ( local result = Exec::run([$cmd=cmd]) )
		{}
       @endif
       f$info$extracted = dest;


	local uid = join_string_set(f$info$conn_uids,"");
	#print(fmt("Adding new Hash: %s for Conn uid: %s",dest,uid));
	hashes_monitor[dest+uid] = 0;


	@if (Version::number >= 50000)
	 
	     when [f] (local verdict = send_hash_to_wildfire(f))
	 {

		do_verdict(verdict,f);

	 }
	@else
	 
	     when (local verdict = send_hash_to_wildfire(f))
	 {
		do_verdict(verdict,f);
	 }
	@endif


	

}


event file_sniff(f: fa_file, meta:fa_metadata){

       if ( meta?$mime_type && match_file_types in meta$mime_type ){
       Files::add_analyzer(f,Files::ANALYZER_SHA256);
       Files::add_analyzer(f,Files::ANALYZER_EXTRACT);
       }
}

