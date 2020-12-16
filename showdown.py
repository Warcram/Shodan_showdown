### To-Do list
### - Import data into Elasticsearch
### - Annotate and enhance data with Logstash; or annotate with ZAnnotate and push to ELK
### - Look to implement Python CLI Library - DONE
### - Get ZGrab working properly - needs to handle all data
### - 
### - 
### - 
### - 
### - 

import requests
import os
import argparse
import cmd
from shutil import which
import json


mappings = {
	21: "ftp",
	22: "ssh",
	23: "telnet",
	25: "smtp",
	53: "dns",
	80: "http",
	110: "pop3",
	111: "rpcbind",
	135: "msrpc",
	139: "netbios-ssn",
	143: "imap",
	443: "https",
	445: "microsoft-ds",
	993: "imap",
	995: "pop3s",
	1723: "pptp",
	3389: "rdp",
	8080: "http"
}


class BannerGrab():
	def __init__(self):
		self.port = 80
		self.service = "http"

	def get_command_string(self):
		print(f"Service: {self.service}")
		return (f"zgrab2 {self.service} -f justips.txt -o grab_results.txt")

	def run(self):
		self.gen_just_ip_file()
		self.get_service()
		if self.service == "dns":
			print(f"Cannot banner grab for {self.service}")
		else:
			os.system(self.get_command_string())

	def gen_just_ip_file(self):
		if "results.txt" in os.listdir("./"):
			with open("results.txt", "r") as f:
				content = f.readlines()
			content = content[1::]
			ips = []
			formatted = content
			self.port = int(formatted[0].split(",")[1])
			self.service = self.get_service()
			for items in content:
				row = items.split(",")
				ips.append(row[0])
				
			with open("justips.txt", "w") as of:
				of.writelines('\n'.join(ips))
			of.close()
		else:
			print("No ZMap results, default settings used.")

	def get_service(self):
		self.service = mappings.get(self.port)


class Scan():
	def __init__(self):
		self.port = "23"
		self.ip_range = "0.0.0.0/0"
		self.frequency = "1500"
		self.verbosity = "3"
		self.max_results = "100"

	def update_config(self, crq):
		if crq[0] == "port":
			self.port = crq[1]
			print(f"Port number set to {self.port} ({self.get_service()})")
		elif crq[0] == "ip":
			self.ip_range = f"{crq[1]}/32"
			self.write_to_whitelist()
			print(f"IP Range set to  {self.ip_range}")
		elif crq[0] == "ip_range":
			self.ip_range = crq[1]
			self.write_to_whitelist()
			print(f"IP Range set to {self.ip_range}")
		elif crq[0] == "frequency" or crq[0] == "freq":
			self.frequency = int(crq[1])
			print(f"Frequency set to {str(self.frequency)}")
		elif crq[0] == "max" or crq[0] == "max_results":
			self.max_results = crq[1]
			print(f"Max results set to {self.max_results}")
		elif crq[0] == "verb" or "verbosity":
			self.verbosity = crq[1]
			print(f"Verbosity set to {self.verbosity}")
		else:
			print("Invalid variable. Try again")

	def get_service(self):
		return mappings.get(int(self.port))

	def write_to_whitelist(self):
		with open(".wl.txt", "w+") as f:
			f.write(self.ip_range)
		f.close()

	def run(self):
		if self.ip_range == "0.0.0.0/0":
			print("\033[91m!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!\033[0m")
			print("You are about to scan the entire internet randomly; please proceed with the necessary caution.")
			print("\033[91m!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!!!WARNING!!\033[0m")
			res = "N"
			res = input("Are you sure you want to continue? (y/N) ").strip()
			if res == "Y" or res == "y":
				pass
			else:
				return None
		self.write_to_whitelist()
		os.system(self.get_command_string())

	def get_command_string(self):
		return f"zmap -N {str(self.max_results)} -r {str(self.frequency)} -p {str(self.port)} -v {str(self.verbosity)} -o results.txt -w .wl.txt -f \"saddr,sport,classification,success\""

	def print_config(self):
		print(f"""Current scan config:\
		\nPort:\t\t| {str(self.port)}\
		\nIP Range:\t| {self.ip_range}\
		\nFrequency:\t| {str(self.frequency)}\
		\nVerbosity:\t| {str(self.verbosity)}\
		\nMax results:\t| {str(self.max_results)}\
		\nCommand string:\t| {self.get_command_string()}""")

class Result():
	def __init__(self, row_data):
		res = row_data.split(",")
		self.sourceaddr = res[0]
		self.sourceport = res[1]
		self.classification = res[2]
		self.success = res[3]

	def print_result(self):
		print(f"{self.sourceaddr} \t{self.sourceport} \t{self.classification} \t\t{self.success}")

def sanity_check():
	if os.geteuid() != 0:
		print("You need root privileges to run this script - git gud.")
		return False
	else:
		if which("zgrab2") is not None:
			pass
		else:
			print("You cant use grab. You need to install Zgrab2 and add it to your $PATH. Not straight forward, go to " + """https://github.com/zmap/zgrab2""")
		if which("zmap") is None:
			print("You need to install zmap.")
			resp = input("Wanna do it now? ")
			if resp == "Y" or resp == "y":
				os.system("sudo apt install zmap")
				return True
			else:
				return False
		else:
			return True


def print_results(num_to_show):
	rows_to_display = 10
	with open("results.txt", "r") as f:
		content = f.readlines()
	f.close()
	if not content:
		print("No results :( ")
	else:
		num_of_results = len(content) - 1
		if int(num_to_show) > num_of_results:
			rows_to_display = num_of_results
		else:
			try:
				rows_to_display = int(num_to_show.replace(" ",""))
			except ValueError as e:
				rows_to_display = 10
		all_results = []
		for row in range(0,rows_to_display + 1):
			if not row:
				headers = content[row].replace("\n","").split(",")
			else:
				all_results.append(Result(content[row].replace("\n","")))
		print(headers[0] + '\t\t' + '\t'.join(headers[1::]))	
		for result in all_results:
			result.print_result()


def print_grab_results(options):
	if "results" not in os.listdir():
		os.mkdir("./results/")
	with open("grab_results.txt") as f:
		content = f.readlines() 
	f.close()
	parsed_content = []
	for entry in content:
		parsed_content.append(json.loads(entry))
	protocol= list(parsed_content[0]['data'].items())[0][0]

	for result in parsed_content:
		ip, status   = result['ip'], result['data'][protocol]['status']
		body = None
		if protocol == "http":
			if status == "success":
				url = result['data'][protocol]['result']['response']['request']['url']
				try:
					body = result['data'][protocol]['result']['response']['body']
				except KeyError as e:
					body = ""
				if body != "":
					with open(f"results/{url['host']}.html", "w+") as f:
						f.write(body)
					full_url = f"file://{os.getcwd()}/results/{url['host']}.html" 
					print(full_url)
		elif protocol == "telnet" or protocol == "imap" or protocol == "smtp" or protocol == "ftp":
			if status == "success":
				banner = result['data'][protocol]['result']['banner']
				if banner != "":
					with open(f"results/{ip}.html", "w+") as f:
						f.write(banner)
					full_url = f"file://{os.getcwd()}/results/{ip}.html"
					print(full_url)


def generate_json():
	with open("results.txt", "r") as f:
		zmap_data = f.readlines()
	with open("grab_results.txt", "r") as f:
		content = f.readlines()
		zgrab_data = []
		for item in content:
			zgrab_data.append(json.loads(item))


	headers = zmap_data[0].split(",")
	zmap_data = zmap_data[1::]
	output = {}

	print_data = []
	for item in range(0,len(zmap_data)):
		print_data.append(zmap_data[item].split(","))

	service = list(zgrab_data[0]["data"].keys())[0]
	for x in range(0,len(headers)):
		for y in range(0,len(zmap_data)):			
			output[print_data[y][0].strip()] = {headers[x].strip(): print_data[y][x].strip()}
			#if zgrab_data[y]["ip"] == print_data[y][0]:
			#	output[print_data[y][0]]["data"] = zgrab_data[y]["data"][service]["result"]["response"]["body"]
	return output


def print_help(startup):
	if startup:
		print("GoScan.py!\nType help if you.... need help?")
	else:
		print("show command:\
		\nshow opt[ions]/conf[ig]\t\tDisplay current scan configuration\
		\nshow res[ults] [X]\t\tDisplay [up to X] results of latest ZMap scan\
		\nshow grab\t\t\tDisplay latest ZGrab Result\
		\n\nset command:\
		\nset port X\t\t\tSet port number you want to find\
		\nset ip X.X.X.X\t\t\tSet specific IP address to scan\
		\nset ip_range X.X.X.X/XX\t\tSet IP range using CIDR Notation\
		\nset freq[uency] X\t\tSet frequency of requests per second\
		\nset verb[osity] X\t\tSet verbosity level of zmap\
		\nset max X\t\t\tSet max number of hosts to find in scan\
		\n\nrun command:\
		\nrun\t\t\t\tRun ZMap scan with current configuration\
		\n\ngrab command:\
		\ngrab\t\t\t\tRun ZGrab scan with latest results")

class Go_Scan_Shell(cmd.Cmd):
	intro = print_help(True)
	prompt = ">> "
	
	def __init__(self):
		super(Go_Scan_Shell, self).__init__()
		self.scan = Scan()
		self.grab = BannerGrab()

	def do_help(self,line):
		print_help(False)

	def do_set(self, variable):
		self.scan.update_config(variable.split())

	def do_show(self, variable):
		args = variable.split()
		if len(args) > 0:
			if args[0] == "conf" or args[0] == "config" or args[0] == "options" or args[0] == "opt":
				self.scan.print_config()
			elif args[0] == "results" or args[0] == "res":
				if len(args) > 1:
					print_results(args[1])
				else:
					print_results("10")
			elif args[0] == "grab":
				if len(args) > 1: 
					print_grab_results(args[1])
				else:
					print_grab_results(10)
		else:
			print_help(False)


	def do_push(self, variable):
		headers = {"User-Agent":"Mozilla/5.0 (Windows NT x.y; Win64; x64; rv:10.0) Gecko/41.0 Firefox/41.0",
				   "Content-Type": "application/json"}
		data = generate_json()
		print(data)
		resp = requests.post("http://192.168.0.21:5044", proxies={"http":"http://localhost:8080"}, headers=headers, data=data)
		if resp == None:
			pass


	def do_grab(self, variable):
		self.grab.run()

	def do_clear(self, varilable):
		os.system("clear")

	def do_ls(self, variable):
		os.system("ls")

	def do_run(self, variable):
		self.scan.run()

	def do_exit(self, line):
		exit(0)

	def do_grab(self, line):
		self.grab.run()


def main():
	proceed = sanity_check()
	if proceed:
		new_scan = Scan()
		banner_grab = BannerGrab()
		ret = True
		entry = 0
		looper = Go_Scan_Shell()
		looper.cmdloop()
		while ret:
			ret = show_menu(entry, new_scan, banner_grab)
			entry += 1
	else:
		return 0

if __name__ == "__main__":
	main()

