import cache_snake
import os
import re
import time
import json
import httpx
import zipfile
import logging
import termcolor
import itertools
import threading
import concurrent.futures

#fetch bug bounty/vulnerability disclosure programs from projectdiscovery chaos
def get_chaos_list(force_fetch=False):
    #use cached file if 24 hours hadn't passed since fetching
    if os.path.exists("chaos_list_timestamp") and not force_fetch:
        with open("chaos_list_timestamp", "r") as ts_file:
            timestamp = int(ts_file.read())
        if (int(time.time()) - timestamp) <= 86400:
            if os.path.exists("chaos_list_cached"):
                with open("chaos_list_cached") as chaos_list_text:
                    return json.loads(chaos_list_text.read())
    
    #else fetch the file from github, cache it and update the timestamp
    chaos_list_response = httpx.get("https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/master/chaos-bugbounty-list.json")
    with open("chaos_list_timestamp", "w") as ts_file:
        ts_file.write(str(int(time.time())))
    with open("chaos_list_cached", "w") as cache_file:
        cache_file.write(chaos_list_response.text)
    return json.loads(chaos_list_response.text)

#get the subdomain list from chaos for a specific program
def get_chaos_subdomains(program_name):
    subdomain_file_name = program_name.lower().replace(' ', '_') + ".zip"
    cached_and_valid = False

    #use cached file if 24 hours hadn't passed since fetching
    if os.path.exists("chaos_subdomain_dir/"+ subdomain_file_name + ".timestamp"):
        with open("chaos_subdomain_dir/"+ subdomain_file_name + ".timestamp", "r") as ts_file:
            timestamp = int(ts_file.read())
        if (int(time.time()) - timestamp) <= 86400:
            if os.path.exists("chaos_subdomain_dir/"+ subdomain_file_name):
                cached_and_valid = True

    if not cached_and_valid:
        chaos_response = httpx.get("https://chaos-data.projectdiscovery.io/" + subdomain_file_name)

        #if not 200 ok go home.
        if chaos_response.status_code != 200:
            return []

        #make directory
        if not os.path.exists("chaos_subdomain_dir"):
            os.mkdir("chaos_subdomain_dir")
        
        #write contents to a zip file
        with open("chaos_subdomain_dir/" + subdomain_file_name, "wb") as f:
            f.write(chaos_response.content)

        #write new timestamp
        with open("chaos_subdomain_dir/" + subdomain_file_name + ".timestamp", "w") as ts:
            ts.write(str(int(time.time())))
    
    #if it's not a zip file go home
    if not zipfile.is_zipfile("chaos_subdomain_dir/" + subdomain_file_name):
        os.remove("chaos_subdomain_dir/" + subdomain_file_name)
        return []

    #read and return contents
    subdomain_list = []
    
    with zipfile.ZipFile("chaos_subdomain_dir/" + subdomain_file_name, "r") as zf:
        compressed_files = zf.namelist()
        for compressed_file_name in compressed_files:
            with zf.open(compressed_file_name, "r") as f:
                subdomain_list += f.read().splitlines()

    return subdomain_list

#get urls for testing 
def get_urls_from_subdomains(subdomain_list, response_timeout=10.0):
    url_list = []
    seen_subdomains = [] # we don't need more than one javascript url from any subdomain so we keep track of urls from subdomains we've alredy seen
    
    for subdomain in subdomain_list:
        #get response from server
        for url_prefix in ["http://", "https://"]:
            if url_prefix + str(subdomain) in url_list:
                continue

            try:
                response = httpx.get(url_prefix + str(subdomain, 'ascii'), follow_redirects=True, timeout=response_timeout)
            except:
                continue

            if response.is_success:
                #add all previous redirects and current url to list
                for redirect_response in response.history:
                    if bytes(redirect_response.url.host, 'ascii') in subdomain_list:
                        url_list.append(str(redirect_response.url))
                if bytes(response.url.host, 'ascii') in subdomain_list:
                    url_list.append(str(response.url))

                #iterate over every script tag, get url, test response, make sure it doesn't already exist and add it to the list
                script_tags = re.findall("<script[^\\>]*src=[\"']?[^'\" ]*[\"']?", response.text)
                for js_url in script_tags:
                    #extract src value from html, if we have a relative url make it absolute
                    js_url = js_url.split("src=")[1]
                    js_url = js_url[1:len(js_url) - 1]
                    if js_url.startswith("//"):
                        js_url = "https:" + js_url
                    elif js_url.startswith("/"):
                        if str(response.url).endswith("/"):
                            js_url = str(response.url) + js_url[1:len(js_url)]
                        else:
                            js_url = str(response.url) + js_url
                    
                    if js_url in url_list:
                        continue

                    #use httpx.URL object to parse url
                    url_obj = httpx.URL(js_url)
                    if bytes(url_obj.host, 'ascii') in subdomain_list and url_obj.host not in seen_subdomains:
                        #try to get a response from server
                        try:
                            js_response = httpx.get(url_obj, timeout=response_timeout)
                        except:
                            continue
                        
                        #if we get successful response add the javascript url to the list and mark the subdomain so we don't get many duplicates
                        if js_response.is_success:
                            url_list.append(js_url)
                            seen_subdomains.append(url_obj.host)
    return url_list

#get a program name, and test it for cache poisoning
def test_chaos_program(program, vuln_file_path="", vuln_file_lock=None):
    logging.info(termcolor.colored("[i]: Testing Program: {}".format(program["name"]), "blue"))

    #get available subdomains
    subdomain_list = get_chaos_subdomains(program["name"])
    if len(subdomain_list) == 0:
        logging.info(termcolor.colored("[i]: Subdomain list for program \"{}\" is empty.".format(program["name"]), "blue"))
        return
    logging.info(termcolor.colored("[i]: Found {1} subdomains for {0}.".format(program["name"], len(subdomain_list)), "blue"))

    
    #get useful urls
    url_list = get_urls_from_subdomains(subdomain_list)
    if len(url_list) == 0:
        logging.info(termcolor.colored("[i]: No URL's found for program \"{}\".".format(program["name"]), "blue"))
        return
    logging.info(termcolor.colored("[i]: Found {1} URL's for {0}.".format(program["name"], len(url_list)), "blue"))

    #
    # attacks are launched sequentially rather than concurrently out of fear
    # that we will get ip banned because these attacks are rather noisy
    # it's better to have concurrency between programs being tested rather
    # than within them.
    #

    vulns = []
    
    for url in url_list:
        specific_attacks_result = cache_snake.specific_attacks(url, program["name"])
        header_bruteforce_result = cache_snake.header_bruteforce(url)
        severity_asessment_result = cache_snake.assess_severity(url, program["name"], header_bruteforce_result)

        specific_attacks_json = []
        if specific_attacks_result.dos_path_override[0]:
            specific_attacks_json.append({"attack_name": "Path Override DoS", "headers": specific_attacks_result.dos_path_override[1]})
        if specific_attacks_result.dos_path_override[2]:
            specific_attacks_json.append({"attack_name": "Likely Path Override DoS", "headers": specific_attacks_result.dos_path_override[1]})
        if specific_attacks_result.dos_path_override[0]:
            specific_attacks_json.append({"attack_name": "Possible Path Override DoS", "headers": specific_attacks_result.dos_path_override[1]})
        if specific_attacks_result.dos_proto_override[0]:
            specific_attacks_json.append({"attack_name": "Protocol Override DoS", "headers": specific_attacks_result.dos_proto_override[1]})
        if specific_attacks_result.rdr_permenant_redirect[0]:
            specific_attacks_json.append({"attack_name": "Permenant Redirect", "headers": specific_attacks_result.rdr_permenant_redirect[1]})
        if specific_attacks_result.dos_port_override[0]:
            specific_attacks_json.append({"attack_name": "Port Override DoS", "headers": specific_attacks_result.dos_port_override[1]})
        if specific_attacks_result.dos_method_override[0]:
            specific_attacks_json.append({"attack_name": "Method Override DoS", "headers": specific_attacks_result.dos_method_override[1]})
        if specific_attacks_result.dos_evil_user_agent[0]:
            specific_attacks_json.append({"attack_name": "Method Override DoS", "headers": specific_attacks_result.dos_evil_user_agent[1]})
        if specific_attacks_result.xss_host_override[0]:
            specific_attacks_json.append({"attack_name": "Host Override XSS", "headers": specific_attacks_result.xss_host_override[1]})
        if specific_attacks_result.dos_host_header_port[0]:
            specific_attacks_json.append({"attack_name": "Host Header Port DoS", "headers": specific_attacks_result.dos_host_header_port[1]})
        if specific_attacks_result.dos_illegal_header[0]:
            specific_attacks_json.append({"attack_name": "Illegal Header DoS", "headers": specific_attacks_result.dos_illegal_header[1]})
            
        header_bruteforce_json = []
        for i in range(len(header_bruteforce_result)):
            if severity_asessment_result[i][0] and (severity_asessment_result[i][1] or severity_asessment_result[i][3] or severity_asessment_result[i][5]):
                header_bruteforce_json.append({"header_name": header_bruteforce_result[i],
                                               "is_cacheable": severity_asessment_result[i][0],
                                               "is_status_code_changed": severity_asessment_result[i][1],
                                               "new_status_code": severity_asessment_result[i][2],
                                               "is_body_reflected": severity_asessment_result[i][3],
                                               "is_body_unfiltered": severity_asessment_result[i][4],
                                               "is_header_reflected": severity_asessment_result[i][5],
                                               "reflection_header_names": severity_asessment_result[i][6]})

        if len(specific_attacks_json) > 0 or len(header_bruteforce_json) > 0:
            url_vuln = {"url": url,
                        "specific_attacks": specific_attacks_json,
                        "header_bruteforce": header_bruteforce_json,
                        "discovered_at": int(time.time())}
        
            vulns.append(url_vuln)
    
    vuln_report = {"program_name": program["name"],
                   "program_url" : program["url"],
                   "vulns"       : vulns}

    with vuln_file_lock:
        with open(vuln_file_path, 'a') as f:
            f.write(json.dump(vuln_report, indent=4))

    logging.info(termcolor.colored("[i]: DONE Testing Program: {}".format(program["name"]), "blue"))



#main function
def main():
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    cache_snake.print_banner()

    logging.info(termcolor.colored("[i]: CHAOS TESTING INITIATED", "blue"))

    chaos_list = get_chaos_list()
    bounty_programs = [program for program in chaos_list["programs"] if program["bounty"]]

    logging.info(termcolor.colored("[i]: Found {} bug bounty programs.".format(len(bounty_programs)), "blue"))

    #for program in bounty_program_names:
    vuln_file_lock = threading.Lock()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        executor.map(test_chaos_program, bounty_programs, itertools.repeat("vuln_file.txt"), itertools.repeat(vuln_file_lock))


if __name__ == "__main__":
    main()