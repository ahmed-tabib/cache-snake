import cache_snake
import json
import httpx
import time
import os

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

chaos_list = get_chaos_list()

bb_list = []
vdp_list = []

for program in chaos_list['programs']:
    if program['bounty']:
        bb_list.append(program)
    else:
        vdp_list.append(program)

print("BB count: {}".format(len(bb_list)))
print("VDP count: {}".format(len(vdp_list)))
print("Total: {}".format(len(chaos_list['programs'])))