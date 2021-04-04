p### To-Do list
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

import requests
import os
import argparse
import cmd
from shutil import which
import json
import argparse
import re
from datetime import datetime

mappings = {
	#PORT: SERVICE
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
	5601: "http",
	8000: "http",
	8080: "http"
}

LOG=False

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
		elif crq[0] == "freque as f:ncy" or crq[0] == "freq":
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
				return False
		if not self.ip_range == "file":
			self.write_to_whitelist()
		os.system(self.get_command_string())
		return True

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

	with open("annotated_ips.txt", "r") as f:
		content = f.readlines()
		geodata = []	
		for item in content:
			geodata.append(json.loads(item))

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


def push_to_elk():
	headers = {"User-Agent":"Mozilla/5.0 (Windows NT x.y; Win64; x64; rv:10.0) Gecko/41.0 Firefox/41.0",
				   "Content-Type": "application/json"}
	#annotate_data()
	data = generate_json()
	#print(f"DATA:{data}")
	clear_file("output.txt")
	for item in data:
		with open("output.txt", "a+") as f:
			f.write(json.dumps(item))
	resp = requests.post("http://192.168.0.21:5044", headers=headers, data=json.dumps(data))
	if resp.status_code == 200:
		print("Success!")
	else:
		print(f"Failed with error code {resp.status_code}")

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

class Go_Scan_Shell(cmd.Cmd):
	intro = print_help(True)
	prompt = ">> "
	
	def __init__(self, args):
		super(Go_Scan_Shell, self).__init__()
		self.scan = Scan(args)
		self.grab = BannerGrab(args)
		self.output = ""

	def do_help(self,line):
		print_help(False)

	def do_set(self, variable):
		self.scan.update_config(variable.split())

	# def do_pipe(self, args):
	# 	buffer = None
	# 	for arg in args:
	# 		s = arg
	# 		if buffer:
	# 			s += ' ' + buffer
	# 		self.onecmd(s)
	# 		buffer = self.output


	# def postcmd(self, stop, line):
	# 	if hasattr(self, 'output') and self.output:
	# 		print_switch(self.output)
	# 		self.output = None
	# 	return stop

	# def precmd(self, line):
	# 	if "|" in line:
	# 		print_switch(line.replace("|","pipe"))
	# 		return line.replace("|","pipe")
	# 	return line

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
			elif args[0] == "output":
				os.system("cat output.txt")
				print("") ## Print blank line as no new line character at end of file
		else:
			print_help(False)


	def do_grep(self, var):
		os.system(f"grep {var}")


	def do_push(self, variable):
		push_to_elk()

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

