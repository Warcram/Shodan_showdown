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

import os
import argparse
import requests
import cmd
import sys
from shutil import which
import json

LOGSTASH_URL = "127.0.0.1"
LOGSTASH_PORT = "8080"


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

bannerGrab_Blacklist = ['dns']

class BannerGrab():
	def __init__(self):
		self.port = 80
		self.service = "http"

	def get_command_string(self):
		print(f"Service: {self.service}")
		if self.service == "https":
			self.service = "http"
		return (f"zgrab2 {self.service} -f justips.txt -o grab_results.txt")

	def submit_to_logstash(self, host, port):
		headers = {"Content-Type": "application/json"}
		for result in os.listdir('./results/'):
			if ".new" not in result:
				print(result)
				with open(f"./results/{result}", "r") as f:
					data = json.load(f)
					response = requests.post(f"http://{host}:{port}", json=data, headers=headers)
					print(response.content)

	def run(self):
		proceed = False
		proceed = self.gen_just_ip_file()
		if proceed:
			self.get_service()
			if self.service in bannerGrab_Blacklist:
				print(f"Cannot banner grab for {self.service}")
			else:
				os.system(self.get_command_string())
				print_grab_results(True)
		else:
			print("Grab failed - check that there are results available from ZMap scan.")

	def gen_just_ip_file(self):
		if "results.txt" in os.listdir("./"):
			with open("results.txt", "r") as f:
				content = f.readlines()
			content = content[1::]
			ips = []
			formatted = content
			try:
				self.port = int(formatted[0].split(",")[1])
			except IndexError as e:
				return False
			
			self.service = self.get_service()
			for items in content:
				row = items.split(",")
				ips.append(row[0])
				
			with open("justips.txt", "w") as of:
				of.writelines('\n'.join(ips))
			of.close()
			return True
		else:
			print("No ZMap results, default settings used.")
			return False

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
		print(f"{self.sourceaddr}\t{self.sourceport} \t{self.classification} \t\t{self.success}")

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
	if "results.txt" in os.listdir("./"):
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
	else:
		print("No results to show at this time. Please run a scan to generate results.")


def print_grab_results(options):
	if "results" not in os.listdir():
		os.mkdir("./results/")
	with open("grab_results.txt") as f:
		content = f.readlines() 
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
		elif protocol == "telnet" or protocol == "imap" or protocol == "smtp" or protocol == "ftp" or protocol == "ssh":
			if status == "success":
				if protocol == "ssh":
					banner = str(result['data'][protocol]['result']['server_id'])
				else:
					banner = result['data'][protocol]['result']['banner']
				if banner != "":
					with open(f"results/{ip}.{protocol}", "w+") as f:
						banner = banner.replace('\'', '\"')
						f.write(banner)
					full_url = f"file://{os.getcwd()}/results/{ip}.{protocol}"
					print(full_url)


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


	def do_grab(self, variable):
		self.grab.run()

	def do_clear(self, variable):
		os.system("clear")

	def do_ls(self, variable):
		os.system("ls")

	def do_run(self, variable):
		self.scan.run()

	def do_exit(self, line):
		exit(0)

	def do_grab(self, line):
		self.grab.run()

def check_for_shell(arguments):
	if "-ip" in arguments or "-p" in arguments:
		return False
	else:
		return True

def parse_args(args):
	parser = argparse.ArgumentParser(
		prog='ShodanShowdown',
		description='An application for running internet scans on specific ranges and ports. Can be used to grab banners.',
	)
	parser.add_argument('-ip', '--ip')
	parser.add_argument('-p', '--port')
	parser.add_argument('-f', '--frequency')
	parser.add_argument('-m', '--max')
	parser.add_argument('-v', '--verbose')
	parser.add_argument('-g', '--grab', action='store_true')
	parser.add_argument('-ips', '--iplist')
	parser.add_argument('-s', '--submit', action='store_true')
	args = parser.parse_args()
	return args

def configure_scan(scan, banner, args):
	args = parse_args(args)
	if args.ip is not None:
		scan.ip_range = args.ip
	if args.port is not None:
		scan.port = args.port
		banner.port = args.port
	if args.frequency is not None:
		scan.frequency = args.frequency
	if args.max is not None:
		scan.max = args.max
	if args.iplist is None:
		scan.run()
		if args.grab:
			banner.run()
			if args.submit:
				banner.submit_to_logstash(LOGSTASH_URL, LOGSTASH_PORT)
	else:
		with open(args.iplist) as f:
			ip_list = f.readlines()
		for ip_range in ip_list:
			scan.ip_range = ip_range
			scan.port = args.port
			scan.run()
			if args.grab:
				banner.run()
				if args.submit:
					banner.submit_to_logstash(LOGSTASH_URL, LOGSTASH_PORT)
	print("Complete.")



def main():
	proceed = sanity_check()
	is_shell = check_for_shell(sys.argv)

	if proceed:
		if is_shell:
			looper = Go_Scan_Shell()
			looper.cmdloop()
		else:
			new_scan = Scan()
			banner_grab = BannerGrab()
			configure_scan(new_scan, banner_grab, sys.argv)
	else:
		return 0

if __name__ == "__main__":
	main()
