#!/bin/bash
# Author: Bala Murali
# Date: 2022/10/12
# Usage: need to write.

#Logo
#logo(){


#}
#logo


#Gather JSFilesUrls
gather_js(){
echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Started Gathering JsFiles-links\e[0m\n";
cat "$target" | gau | grep -iE "\.js$" | uniq | sort >> jsfile_links.txt
cat "$target" | subjs >> jsfile_links.txt
#cat $target | hakrawler -js -depth 2 -scope subs -plain >> jsfile_links.txt
echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Checking for live JsFiles-links\e[0m\n";
cat jsfile_links.txt | httpx -follow-redirects -silent -status-code | grep "[200]" | cut -d ' ' -f1 | sort -u > live_jsfile_links.txt
}

#Open JSUrlFiles
open_jsurlfile(){
echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Filtering JsFiles-links\e[0m\n";
cat "$target" | httpx -follow-redirects -silent -status-code | grep "[200]" | cut -d ' ' -f1 | sort -u > live_jsfile_links.txt
}

#Gather Endpoints From JsFiles
endpoint_js(){
echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Started gathering Endpoints\e[0m\n";
interlace -tL live_jsfile_links.txt -threads 5 -c "echo 'Scanning _target_ Now' ; python3 ./tools/LinkFinder/linkfinder.py -d -i '_target_' -o cli >> endpoints.txt" -v
}

#Gather Secrets From Js Files
secret_js(){
echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Started Finding Secrets in JSFiles\e[0m\n";
interlace -tL live_jsfile_links.txt -threads 5 -c "python3 ./tools/SecretFinder/SecretFinder.py -i '_target_' -o cli >> jslinksecret.txt" -v
}

#Collect Js Files For Maually Search
getjsbeautify(){
echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Started to Gather JSFiles locally for Manual Testing\e[0m\n";
mkdir -p jsfiles
interlace -tL live_jsfile_links.txt -threads 5 -c "bash ./tools/getjsbeautify.sh '_target_'" -v
echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Manually Search For Secrets Using gf or grep in out/\e[0m\n";
}

#Gather JSFilesWordlist
wordlist_js(){
echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Started Gathering Words From JsFiles-links For Wordlist.\e[0m\n";
cat live_jsfile_links.txt | python3 ./tools/getjswords.py >> temp_jswordlist.txt
cat temp_jswordlist.txt | sort -u >> jswordlist.txt
rm temp_jswordlist.txt
}

#Gather Variables from JSFiles For Xss
var_js(){
echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Started Finding Varibles in JSFiles For Possible XSS\e[0m\n";
cat live_jsfile_links.txt | while read url ; do bash ./tools/jsvar.sh $url | tee -a js_var.txt ; done
}

xss(){
    echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Scanning the target For Possible XSS\e[0m\n";
    interlace -tL "$target" -threads 5 -c "python3 ./tools/PwnXSS/pwnxss.py -u _target_ >> xss_output.txt" -v

}

cors(){
    echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Scanning the target For Possible CORS Attack\e[0m\n";
    python3 ./tools/CORScanner/cors_scan.py -i "$target" -t 100 -v -o cors_output.txt

}

hrs(){
    echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Scanning the target For Possible HTTP Request Smuggling Attack\e[0m\n";
    cat "$target" | python3 ./tools/smuggler/smuggler.py >> hrs_output.txt

}

#Generate Report
'''report(){
echo -e "\n\e[36m[\e[32m+\e[36m]\e[92m Generating Report!\e[0m\n";
bash report.sh
}'''

#Save in Output Folder
output(){
mkdir -p $dir
mv endpoints.txt jsfile_links.txt jslinksecret.txt live_jsfile_links.txt jswordlist.txt js_var.txt xss_output.txt cors_output.txt hrs_output.txt $dir/ 2>/dev/null
mv jsfiles/ $dir/
}
while getopts ":l:f:esmwvxcho:-:" opt;do
	case ${opt} in
		- )      case "${OPTARG}" in

			all) 
				endpoint_js
				secret_js
				getjsbeautify
				wordlist_js
				var_js
				xss
				cors
				hrs
				;;

			*)
                                        if [ "$OPTERR" = 1 ] && [ "${optspec:0:1}" != ":" ]; then
                                        echo "Unknown option --${OPTARG}" >&2
                                        fi
                                        ;;
                        esac;; 

		l ) target=$OPTARG
		    gather_js
		    ;;
        f ) target=$OPTARG
		    open_jsurlfile
		    ;;
		e ) endpoint_js
		    ;;
		s ) secret_js
		    ;;
		m ) getjsbeautify
		    ;;
		w ) wordlist_js
                    ;;
		v ) var_js
		    ;;
		x ) xss
		    ;;
		c ) cors
		    ;;
		h ) hrs
		    ;;
		#r ) report
		#    ;;
		o ) dir=$OPTARG
		    output
		    ;;
	\? | h ) echo "Usage: "
		     echo "       -l   Gather Js Files Links";
		     echo "       -f   Import File Containing JS Urls";
             echo "       -e   Gather Endpoints For JSFiles";
		     echo "       -s   Find Secrets For JSFiles";
		     echo "       -m   Fetch Js Files for manual testing";
		     echo "       -o   Make an Output Directory to put all things Together";
		     echo "       -w   Make a wordlist using words from jsfiles";
		     echo "       -v   Extract Vairables from the jsfiles";
		     echo "       -x   Scan for Possible XSS";
			 echo "       -c   Scan for Possible CORS";
			 echo "       -h   Scan for Possible HTTP Request Smuggling";
		    # echo "       -r   Generate Scan Report in html";
		     echo "	  --all Scan Everything!";
		     ;;
		: ) echo "Invalid Options $OPTARG require an argument";
		    ;;
	esac
done
shift $((OPTIND -1))