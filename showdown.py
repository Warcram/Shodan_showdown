### To-Do list
### - Import data into Elasticsearch - DONE
### - Annotate and enhance data with Logstash; or annotate with ZAnnotate and push to ELK - DONE
### - Look to implement Python CLI Library - DONE
### - Get ZGrab working properly - needs to handle all data
### - Import banner grab data to ELK - perhaps service name and version?
### - Get service mappings from remote repository
### - Get TLS version from grab if possible
### - Get OS Type/Version from grab or TTL?
### - Keyword search within banner grab and flag as suspicious
### - Create a way for showdown to be ran as a command rather than CLI - In Prog

import csv
import requests
import os
import argparse
import cmd
from shutil import which
import json
import argparse
import re
from datetime import datetime
from math import floor


def get_mappings():
	with open("small_mappings.json","r",encoding='utf-8') as jsonf:
		mappings = json.loads(jsonf.read())
	return mappings

mappings = get_mappings()

LOG=False

def update_mappings():
	url = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
	raw_csv = requests.get(url, allow_redirects=True)
	with open("new_mappings_full.csv","w") as f:
		content = raw_csv.content.decode('utf-8')
		f.write(content)
	print(content)
	f.close()
	data = {}
	compressed_data = {}
	with open("new_mappings_full.csv", encoding="utf-8") as csvf:
		reader = csv.DictReader(csvf)
		for rows in reader:
			key = rows['Port Number']	
			data[key] = rows
			compressed_data[key] = rows["Service Name"]
	with open("mappings.json", "w", encoding='utf-8') as jsonf:
		all_data = json.dumps(data,indent=4)
		jsonf.write(all_data)
	with open("small_mappings.json","w", encoding='utf-8') as jsonf:
		small_data = json.dumps(compressed_data, indent=4)
		jsonf.write(small_data)
		print(small_data)


def print_title(txt, max=None):
	if max:
		mx = max
	mx = 75 # Max can be overriden when called, but will still be overwritten if the string is too long
	str_len = len(txt)
	if str_len > mx:
		mx = str_len + 50	
	rem = mx - (str_len + 6)  # +6 for extra characters in print string
	ind_banner = floor(rem/ 2) + rem % 2 # Length of each individual banner excluding endpoints
	x = "="*ind_banner # Bad variable name for shorter print string
	print(f"\n|{x}| \033[1m{txt}\033[0m |{x}|\n") 


class BannerGrab():
	def __init__(self, args):
		self.port = 80
		self.service = "http"
		self.args = args

	def get_command_string(self):
		print(f"Service: {self.service}")
		if self.service == "https":
			self.service = "http"
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
	def __init__(self, args):
		self.port = "23"
		self.ip_range = "0.0.0.0/0"
		self.frequency = "1500"
		self.verbosity = "3"
		self.max_results = "100"
		self.args = args

	def update_config(self, crq):
		if crq[0] == "port":
			self.port = crq[1]
			print(f"Port number set to {self.port} ({self.get_service()})")
		elif crq[0] == "ip":
			if crq[1] == "file":
				self.ip_range = "file"
				print(f"IP to be pulled from .wl.txt")
			else:
				self.ip_range = f"{crq[1]}/32"
				self.write_to_whitelist()
				print(f"IP Range set to  {self.ip_range}")
		elif crq[0] == "ip_range":
			if crq[1] == "file":
				self.ip_range = "file"
				print(f"IP range to be pulled from .wl.txt")
			else:
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
		return mappings.get(self.port)

	def write_to_whitelist(self):
		with open(".wl.txt", "w+") as f:
			f.write(self.ip_range)
		f.close()

	def run(self):
		if self.ip_range == "0.0.0.0/0":
			print_title("\033[91mWARNING\033[0m")
			print("You are about to scan the entire internet randomly; please proceed with the necessary caution.")
			print_title("\033[91mWARNING\033[0m")
			res = "N"
			res = input("Are you sure you want to continue? (y/N) ").strip()
			if res == "Y" or res == "y":
				pass
			else:
				return False
		if not self.ip_range == "file":
			self.write_to_whitelist()
		os.system(self.get_command_string())
		return True

	def get_command_string(self):
		return f"zmap -N {str(self.max_results)} -r {str(self.frequency)} -p {str(self.port)} -v {str(self.verbosity)} -o results.txt -w .wl.txt  -f \"saddr,sport,classification,success,ttl,timestamp-str\""

	def print_config(self):
		print_title("ZMap Config")
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
		self.ttl = res[4]
		self.timestamp = res[5].replace("T"," ")[:19]

	def print_result(self):
		print(f"{self.sourceaddr} \t{self.sourceport} \t{self.classification} \t\t{self.success}\t{self.ttl}\t{self.timestamp}")

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
		print_switch(headers[0] + '\t\t' + '\t'.join(headers[1::]))	
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


def annotate_data():
	os.system("cat justips.txt | ./zannotate --geoip2 --geoip2-database=GeoLite2-City.mmdb > annotated_ips.txt")

def file_exists(filename):
	return os.path.exists(filename)

def print_switch(string):
	global LOG
	todays_date = datetime.today().strftime('%Y%m%d')
	file_name = f"showdown-{todays_date}.log"
	open_method = "w+"
	if LOG:
		if file_exists(file_name):
			open_method = "a+"
		with open(file_name, open_method) as f:
			f.write(f"{string}\n")
	else:
		print(string)



def generate_json():
	with open("results.txt", "r") as f:
		#### ZMAP Data contains just general info on whether scan was successful, IP and port ####
		zmap_data = f.readlines()
	with open("grab_results.txt", "r") as f:
		#### ZGrab data contains response information from banner grab, such as content of HTTP requests etc ####
		content = f.readlines()
		zgrab_data = []
		for item in content:
			zgrab_data.append(json.loads(item))

	# with open("annotated_ips.txt", "r") as f:
	# 	content = f.readlines()
	# 	geodata = []	
	# 	for item in content:
	# 		geodata.append(json.loads(item))

	headers = zmap_data[0].split(",")
	zmap_data = zmap_data[1::]
	#### Output is a list of dictionaries which will be iterated through in the Push to ELK ####
	output = []
	items = []
	objs = []
	for row in zmap_data:
		#### Seperate out each item into a list of "items" ####
		items.append(row.split(","))
	for row in items:
		for entry in row:
			obj = {headers[row.index(entry)]:entry}
			objs.append(obj) 
	obj = {}
	#print_switch(items)
	for row in range(0,len(objs)): #### For every item in ZMAP_Data 
		for header in range(0,len(headers)): #### Every header for each IP
			if row % 4 == 0:
				for data in zgrab_data:
					if data["ip"] == objs[row]["saddr"]:
						output.append({"saddr": objs[row]["saddr"], "sport": objs[row+1]["sport"], "http_status":data["data"]["http"]["status"], "success": objs[row+3]["success\n"]})
			else:
				pass
	return output


def clear_file(filename):
	with open(filename, "w+") as f:
		f.write("")


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
		\ngrab\t\t\t\tRun ZGrab scan with latest results\
		\n\npush command:\
		\npush\t\t\t\tPush most recent scans to ELK")

def validate_port(num):
	try:
		number = int(num)
		if number > 0 and number < 65534:
			return True
		else:
			return False
	except ValueError as e:
		return False


class ELK_Instance():
	def __init__(self):
		self.port = "5044"
		self.url = "http://192.168.0.1"

	def print_config(self):
		print_title("ELK Config")
		print(f"Logstash URL:\t| {self.url}")
		print(f"Logstash Port:\t| {self.port}")

	def get_full_url(self):
		return f"{self.url}:{self.port}"

	def set_url(self,new_url):
		valid_ip_regex = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

		if new_url[0:7] == "http://" or new_url[0:8] == "https://": ### Checking to see if http protocol is at start of string
			new_str = new_url
		else:
			new_str = "http://" + new_url
		if valid_ip_regex.match(new_str[7::]):
			print(f"\033[93mLogstash URL set to {new_str}\033[0m")
			self.url = new_str
		else:
			print(f"\033[91mValidation failure for {new_url}.\033[0m")

	def set_port(self, new_port):
		if validate_port(new_port):
			print(f"\033[93mLogstash port set to {new_port}\033[0m")
			self.port = new_port
		else:
			print("\033[91mInvalid integer, try again\033[0m")

	def push(self):
		headers = {"User-Agent":"Mozilla/5.0 (Windows NT x.y; Win64; x64; rv:10.0) Gecko/41.0 Firefox/41.0",
				   "Content-Type": "application/json"}
		data = generate_json()
		with open("output.txt", "w+") as f:
			f.write(json.dumps(data))
		resp = requests.post(f"{self.get_full_url()}", headers=headers, data=json.dumps(data))
		if resp == None:
			pass


class Go_Scan_Shell(cmd.Cmd):
	intro = print_help(True)
	prompt = ">> "
	
	def __init__(self, args):
		super(Go_Scan_Shell, self).__init__()
		self.scan = Scan(args)
		self.grab = BannerGrab(args)
		self.elk = ELK_Instance()
		self.output = ""

	def help_clear(self):
		print("Clear terminal screen")

	def help_exit(self):
		print("Exits application cleanly")

	def help_grab(self):
		print("Runs ZGrab using the settings from the latest ZMap scan from the run command.")

	def help_ls(self):
		print("Prints the contents of the current working directory")

	def help_push(self):
		print("Pushes the latest results from ZMap to your configured Logstash Instance. Can be configured with the set command")
		self.elk.print_config()

	def help_run(self):
		print("Runs a ZMap scan with the current configuration. You can show this configuration with \"show conf\" command")
		self.scan.print_config()

	def help_set(self):
		print("Configure number of settings listed below:\n")
		print_title("ZMap Configuration")
		print("set port X\t\t\tSet port number you want to find\
		\nset ip X.X.X.X\t\t\tSet specific IP address to scan\
		\nset ip_range X.X.X.X/XX\t\tSet IP range using CIDR Notation\
		\nset freq[uency] X\t\tSet frequency of requests per second\
		\nset verb[osity] X\t\tSet verbosity level of zmap\
		\nset max X\t\t\tSet max number of hosts to find in scan\n")
		print_title("ELK Configuration")
		print("set url <HOSTNAME_OR_IP>\tSet Logstash URL not including port number")
		print("set elk_port 0-65535\t\tSet Logtash port number to send data to")

	def help_show(self):
		print("The show command can be used to display results, configurations and outputs from the ZMap and ZGrab applications.")
		print_title("Configurations")
		print("show conf[ig] - Display current configuration for both scans and ELK configurations")
		print("show opt[ions] - Display current configuration for both scans and ELK configurations")
		print_title("Results")
		print("show res[ults] [x] - Lists the responses of up to 10 results by default. This limit can be modified by appending the number of results to return")
		print("show grab [x] - Shows up to 10 results from the latest ZGrab scan. The limit can be modified by appending the number of results to return")


	def do_test(self, variable):
		pass
		

	def do_set(self, variable):
		args = variable.split()
		if args[0] == "url":
			self.elk.set_url(args[1])
		elif args[0] == "elk_port":
			self.elk.set_port(args[1])
		else:
			self.scan.update_config(variable.split())


	def do_show(self, variable):
		args = variable.split()
		if len(args) > 0:
			if args[0] == "conf" or args[0] == "config" or args[0] == "options" or args[0] == "opt":
				self.scan.print_config()
				self.elk.print_config()
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
			elif args[0] == "output":
				os.system("cat output.txt")
				print("") ## Print blank line as no new line character at end of file
		else:
			print_help(False)


	def do_push(self, variable):
		self.elk.push()

	def do_update(self, variable):
		update_mappings()

	def do_grab(self, variable):
		self.grab.run()

	def do_clear(self, variable):
		os.system("clear")

	def do_ls(self, variable):
		os.system("ls")

	def do_run(self, variable):
		res = self.scan.run()

	def do_exit(self, line):
		exit(0)

	def do_grab(self, line):
		self.grab.run()


class ScriptHandler():
	def __init__(self,args):
		global LOG
		LOG = args.l
		self.non_interactive = args.n
		self.ip_range = args.i
		self.port = args.p
		self.max = args.m
		self.frequency = args.f
		self.zmap_scan_only = args.s
		self.zgrab_scan = args.g
		self.full_scan = args.a
		self.args = args

	def validate_arguments(self):
		valid_ip_regex = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$")
		if (self.ip_range is None or self.port is None):
			print("Non-Interactive mode requires both IP range and Port flag to be set. Please add -h if you need help.")
			self.args.print_help()
			exit(1)
		try:
			self.port=int(self.port)
			if self.port < 65535 and self.port > 0:
				self.port = str(self.port)
			else:
				print("Invlaid port number. Must be in range 0-65534")
				exit(0)
		except TypeError as e:
			print("Invalid port number, must be integer.")
			exit(1)
		if not valid_ip_regex.match(self.ip_range):
			if self.ip_range != "file":
				print("Invalid IPv4 address with CIDR notation. Format is x.x.x.x/x")
				exit(0)

	def configure_scan(self):
		desired_scan = Scan(self.args)
		desired_scan.update_config(["ip_range",self.ip_range])
		desired_scan.update_config(["port", self.port])
		if self.max is not None:
			desired_scan.update_config(["max_results", self.max])
		if self.frequency is not None:
			desired_scan.update_config(["frequency", self.frequency])
		return desired_scan


	def compile(self):
		self.validate_arguments()
		## First, determine scan type
		if self.zmap_scan_only:
			scan = self.configure_scan()
			res = scan.run()
		elif self.zgrab_scan:
			scan = self.configure_scan()
			res = scan.run()
			if res is True:
				grab = BannerGrab(self.args)
				grab.run()
		elif self.full_scan:
			scan = self.configure_scan()
			res = scan.run()
			if res is True:
				grab = BannerGrab(self.args)
				grab.run()
				push_to_elk()
		else:
			print("Please specify type of scan")
			exit(1)


def parse_arg():
	parser = argparse.ArgumentParser(description='Showdown! Internet scanner that you can push to ELK')
	parser.add_argument('-n', help='Enables non-interactive mode, allowing commands to be run directly from a shell.', action='store_true')
	parser.add_argument('-i', metavar='I', type=str, help='IP range with CIDR notation to determine range to scan')
	parser.add_argument('-p', metavar='P', type=str, help='Port number to scan [0-65534]')
	parser.add_argument('-s', help='Run ZMap Scan Only', action='store_true')
	parser.add_argument('-g', help='Run Zmap scan and ZGrab scan sequentially', action='store_true')
	parser.add_argument('-a', help='Run all scans and push to ELK', action='store_true')
	parser.add_argument('-m', help='Maximum number of results to return', type=int)
	parser.add_argument('-f', help='Frequency to send requests', type=int)
	parser.add_argument('-l', help='Log output, rather than print to stdout', action='store_true')
	args = parser.parse_args()
	return args


def main():
	args = parse_arg()
	proceed = sanity_check()
	if proceed: ## Passed all sanity checks
		if not args.n: ## If not running in non-interactive mode
			new_scan = Scan(args) ## Run CLI
			banner_grab = BannerGrab(args)
			ret = True
			entry = 0
			looper = Go_Scan_Shell(args)
			looper.cmdloop()
			while ret:
				ret = show_menu(entry, new_scan, banner_grab)
				entry += 1
		else:
			script = ScriptHandler(args) ## Run non-interactive mode
			script.compile()
		
	else:
		return 0

if __name__ == "__main__":
	main()

