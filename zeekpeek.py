#!/usr/bin/env python3 -tt
import argparse
import os
import re
import subprocess
import sys
import time
from collections import Counter


parser = argparse.ArgumentParser()
parser.add_argument("directory", nargs=1, help="directory of zeek logs")
parser.add_argument("threshold", nargs=1, help="max. # of queries")

args = parser.parse_args()
directory = args.directory
threshold = args.threshold

directory = directory[0]
threshold = int(threshold[0])

def main():
	print("\n")
	convos, queries, responses = [], [], []
	domain_count, ip_count = {}, {}
	if os.path.isdir(directory):
		zeekdir = os.path.abspath(directory)
		print("   > Collating all DNS queries and responses...")
		for zroot, zdirs, zfiles in os.walk(zeekdir):
			for zfile in zfiles:
				zeekfile = os.path.join(zroot, zfile)
				if (os.path.isfile(zeekfile) and zfile.startswith("dns") and zeekfile.endswith(".gz")):
					zeeklogdir = "/".join(list(zeekfile.split("/"))[0:-2])
					if os.path.exists(os.path.join(zeeklogdir, "zeek_all.log")):
						os.remove(os.path.join(zeeklogdir, "zeek_all.log"))
					else:
						pass
				else:
					pass
		for zroot, zdirs, zfiles in os.walk(zeekdir):
			for zfile in zfiles:
				zeekfile = os.path.join(zroot, zfile)
				if (os.path.isfile(zeekfile) and zfile.startswith("dns") and zeekfile.endswith(".gz")):
					zeeklogdir = "/".join(list(zeekfile.split("/"))[0:-2])
					zeeklogpath = os.path.join(zeeklogdir, "zeek_all.log")
					zeek_out_content = str(subprocess.Popen(["gzip", "-dkc", zeekfile], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()[0])[2:-3]
					with open(zeeklogpath, "a") as zeek_out:
						zeek_out.write(zeek_out_content.replace("\\n","\n"))
				else:
					pass
		with open(zeeklogpath) as dns_entries:
			for line in dns_entries:
				response, query = re.findall(r'"id.resp_h":"([^"]+)","id.resp_p":.*"query":"([^"]+)"', line.strip())[0]
				domainorip = re.findall(r"((?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\.in-addr.arpa)?|(?:[^\.]+\.[^\.]+(?:\.[^\.]{2}))?$)", query)
				if domainorip[0].endswith(".in-addr.arpa"):
					domainorip = domainorip[0].split(".in-addr.arpa")[0]
					ip_octets = list(reversed(domainorip.split(".")))
					domainorip = ".".join(ip_octets)
				else:
					domainorip = domainorip[0]
				convos.append("{},{}".format(domainorip,response))
				queries.append(domainorip)
				responses.append(response)


	else:
		print("\n '{}' is not a directory.\n  Please try again\n\n".format(directory))
		sys.exit()
	if len(queries) > 0:
		with open(os.path.join(zeeklogdir, "conversations.csv"), "w") as dns_convos:
			dns_convos.write("query,reponse\n")
		with open(os.path.join(zeeklogdir, "queries.csv"), "w") as dns_queries:
			dns_queries.write("query,count\n")
		with open(os.path.join(zeeklogdir, "responses.csv"), "w") as dns_responses:
			dns_responses.write("reponse,count\n")
		for convo in convos:
			with open(os.path.join(zeeklogdir, "conversations.csv"), "a") as dns_convos:
				dns_convos.write("{}\n".format(convo))
		for domain in queries:
			if domain in domain_count:
				domain_count[domain] += 1
			else:
				domain_count[domain] = 1
		for each_domain, domain_count in domain_count.items():
			if (domain_count <= threshold) or (threshold == 0):
				with open(os.path.join(zeeklogdir, "queries.csv"), "a") as dns_queries:
					dns_queries.write("{},{}\n".format(each_domain, domain_count))
				print("     {}  \tinstances (Q) of '{}'".format(domain_count, each_domain))
				time.sleep(0.2)
			else:
				pass
		for ip in responses:
			if ip in ip_count:
				ip_count[ip] += 1
			else:
				ip_count[ip] = 1
		for each_ip, ip_count in ip_count.items():
			if ip_count < threshold:
				with open(os.path.join(zeeklogdir, "responses.csv"), "a") as dns_responses:
					dns_responses.write("{},{}\n".format(each_ip, ip_count))
				print("     {}  \tinstances (R) of '{}'".format(ip_count, each_ip))
				time.sleep(0.2)
			else:
				pass
		print("\n\n")
	else:
		print("\n No DNS records found.\n  Please try again\n\n")

if __name__ =="__main__":
    main()