@load base/frameworks/files
@load base/files/hash
@load base/frameworks/notice
@load base/utils/active-http
@load base/utils/patterns

module WildFireSandbox;

#TODO add CURL WILDFIRE RETURN ERROR
#TODO notice with attributes for dynamic notices
#TODO Recheck what file types our wildfire accepts

export {

       global WildFireSandbox::recheck_hash: event(f: fa_file);
       redef ActiveHTTP::default_method = "POST" ;
       redef enum Notice::Type += {
               Match
       };

       # Interval - after will retry to get verdict for Pending Hashes or File Sumbits
       option API_KEY = "<API-KEY>" ;
       option WILDFIRE_SERVER = "<SERVER-IP>";
       option VERIFY_TLS = T;
       option sleep_interval = 1min;
       
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

 
 

function send_notice(verdict: string,f: fa_file){

	       local uid = join_string_set(f$info$conn_uids,"");
	       local src: addr;
	       for ( s in f$info$tx_hosts ){
	       		src = s;
	       }
	       local dst: addr;
	       for ( s in f$info$rx_hosts ){
	       		dst = s;
	       }
	       local protocol = f$source;
           
               local n: Notice::Info = Notice::Info($note=Match,$uid=uid,$src=src,$fuid=f$info$fuid,$dst=dst,$msg=fmt("%s Detected",verdictDict[verdict]),$sub=fmt("Malicious file with SHA256: %s detected over %s with format %s",f$info$sha256,protocol,f$info$mime_type));
               NOTICE(n);


}




function send_hash_to_wildfire(f: fa_file): string{

       local hash = f$info$sha256;
       local form_data = " -F 'apikey="+API_KEY+"' -F 'hash="+hash+"'";
	   if (!VERIFY_TLS){
			form_data = " -k "+form_data;
	   }
       local url = WILDFIRE_SERVER+get_verdict;
       local req = ActiveHTTP::Request($url=url,$addl_curl_args=form_data);

       return  when (local response = ActiveHTTP::request($req=req))
       {
               if (response$code == 200){
                       local body = response$body;
                       local verdict = match_pattern(body,/<verdict>([-]?[0-9]{1,3})<\/verdict>/);
                       local verdict_str = verdict$str[9:-10];
                       return (verdict_str);
               }
       }

}


function send_file_to_wildfire(f: fa_file) {

       local hash = f$info$sha256;
       local form_data = " -F 'apikey="+API_KEY+"' -F 'file=@./extract_files/"+hash+"'";
	   if (!VERIFY_TLS){
			form_data = " -k "+form_data;
	   }
       local url = WILDFIRE_SERVER+submit_file;
       local req = ActiveHTTP::Request($url=url,$addl_curl_args=form_data);

       when (local response = ActiveHTTP::request($req=req))
       {
               if (response$code != 200){
                       #print(response$code);
                       return ;
               }
      
       }
}

function do_verdict(verdict: string,f: fa_file){
    
        if (verdict in verdict_to_notify){
        
            send_notice(verdict,f);
        }
        
        if (verdict == "-100"){
                #print(verdictDict[verdict]);
                schedule sleep_interval { WildFireSandbox::recheck_hash(f)};
        
        }

        if (verdict == "-102"){
                #print("Send file");
                send_file_to_wildfire(f);
                schedule sleep_interval { WildFireSandbox::recheck_hash(f)};

               }

}



event WildFireSandbox::recheck_hash(f: fa_file){
       #print(fmt("recheck %s",f$info$sha256));
       when ( local verdict = send_hash_to_wildfire(f)){
               print(verdict);
               do_verdict(verdict,f);
       }
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
       when ( local result = Exec::run([$cmd=cmd]) )
               {
               }
       f$info$extracted = dest;

       when (local verdict = send_hash_to_wildfire(f)){

                #print(fmt("%s %s: %s",orig,f$info$sha256,verdict));
               
                do_verdict(verdict,f);

       }

}


event file_sniff(f: fa_file, meta:fa_metadata){

       if ( meta?$mime_type && match_file_types in meta$mime_type ){
       Files::add_analyzer(f,Files::ANALYZER_SHA256);
       Files::add_analyzer(f,Files::ANALYZER_EXTRACT);
       }
}
