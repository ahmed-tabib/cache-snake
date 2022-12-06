import cache_snake
import os
import re
import time
import json
import httpx
import zipfile
import logging
import termcolor
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
def test_chaos_program(program_name):
    logging.info(termcolor.colored("[i]: Testing Program: {}".format(program_name), "blue"))

    #get available subdomains
    subdomain_list = get_chaos_subdomains(program_name)
    if len(subdomain_list) == 0:
        logging.info(termcolor.colored("[i]: Subdomain list for program \"{}\" is empty.".format(program_name), "blue"))
        return
    logging.info(termcolor.colored("[i]: Found {1} subdomains for {0}.".format(program_name, len(subdomain_list)), "blue"))

    
    #get useful urls
    url_list = get_urls_from_subdomains(subdomain_list)
    if len(url_list) == 0:
        logging.info(termcolor.colored("[i]: No URL's found for program \"{}\".".format(program_name), "blue"))
        return
    logging.info(termcolor.colored("[i]: Found {1} URL's for {0}.".format(program_name, len(url_list)), "blue"))

    #
    # attacks are launched sequentially rather than concurrently out of fear
    # that we will get ip banned because these attacks are rather noisy
    # it's better to have concurrency between programs being tested rather
    # than within them.
    #

    #try specific attacks first
    for url in url_list:
        cache_snake.specific_attacks(url)
    
    #try header bruteforce
    for url in url_list:
        header_bruteforce_result = cache_snake.header_bruteforce(url)
        cache_snake.assess_severity(url, header_bruteforce_result)

    logging.info(termcolor.colored("[i]: DONE Testing Program: {}".format(program_name), "blue"))



#main function
def main():
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    
    cache_snake.print_banner()

    logging.info(termcolor.colored("[i]: CHAOS TESTING INITIATED", "blue"))

    chaos_list = get_chaos_list()
    bounty_program_names = [program["name"] for program in chaos_list["programs"] if program["bounty"]]

    logging.info(termcolor.colored("[i]: Found {} bug bounty programs.".format(len(bounty_program_names)), "blue"))

    #for program in bounty_program_names:
    #    test_chaos_program(program)
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
        executor.map(test_chaos_program, bounty_program_names)


if __name__ == "__main__":
    main()