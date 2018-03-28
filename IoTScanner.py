from tkinter import Tk, Label, Button, StringVar, Listbox
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
# import subprocess
import socket
import threading
import queue
import urllib.request
# import xml.etree.ElementTree as ET
import re

ips = []
detailed_ips = {}


class scan_GUI():

    def __init__(self, master):
        self.master = master
        master.title("IoT device Scanner")
        self.scanrunning = 0  # toggle for if a scan is currently running
        self.scanvar = StringVar()  # string for scan status label
        self.scanvar.set("Scan not running")
        self.scanrunning_label_text = Label(master, textvariable=self.scanvar)
        self.scanrunning_label_text.pack()

        self.ipvar = StringVar()  # string for local ip label
        self.ipvar.set("local IP unknown")
        self.ip_label_text = Label(master, textvariable=self.ipvar)
        self.ip_label_text.pack()

        # button to start a scan
        self.scan_button = Button(master, text="Start scan",
                                  command=self.startscan)
        self.scan_button.pack()
        # listbox for ip addresses
        self.ipList = Listbox(master, width=100)
        self.ipList.pack()
        # button to download CVE data (TEST)
        self.download_button = Button(master,
                                      text="download vulnerability list",
                                      command=download_vulnerability_list)
        self.download_button.pack()

    def startscan(self):
        if self.scanrunning:
            print("Scan already running!")
        else:
            self.scanvar.set("scan running")
            self.scanrunning = 1

            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 53))
            localIP = s.getsockname()[0]
            self.ipvar.set("local IP: " + localIP)
            localIP = localIP + '/24'
            root.update()

            self.queue = queue.Queue()
            ThreadedScan(self.queue, localIP).start()
            self.master.after(100, self.process_queue)
            # Threaded_detailed_scan(self.queue).start()
            # self.master.after(100, self.process_queue)

    def process_queue(self):
        try:
            msg = self.queue.get(0)
            print(msg)
            # self.scanrunning = 0
            if msg == "Initial scan finished":
                self.scanvar.set("Inital Scan finished" +
                                 "- starting detailed scans")
                self.ipList.delete(0, self.ipList.size())
                self.fill_listbox(ips, self.ipList)
                Threaded_detailed_scan(self.queue).start()
                self.master.after(100, self.process_queue())
            elif msg == "detailed scan finished":
                self.scanrunning = 0
                self.scanvar.set("Detailed Scan finished")
        except queue.Empty:
            self.master.after(100, self.process_queue)

    def fill_listbox(self, ip_list, target_listbox):
        lstCount = 0
        for ip in ip_list:
            target_listbox.insert(lstCount, ip.address)
            lstCount += 1


class ThreadedScan(threading.Thread):  # class for intial ip scan
    def __init__(self, queue, localIP):
        threading.Thread.__init__(self)
        self.queue = queue
        self.localIP = localIP

    def run(self):
        # run an nmap scan outputting result to a file, put task finished to
        # queue when it ends
        report = self.run_scan(self.localIP)
        if report:
            print_scan(report)
            add_hosts_to_list(report, ips)
            # get_ips_from_scan(report)
        else:
            print("No results returned")
        self.queue.put("Initial scan finished")

    def run_scan(self, IP):
        # self.queue.put("Starting scan for: " + self.localIP)
        parsed = None
        nmproc = NmapProcess(IP, "-sP")
        rc = nmproc.run()
        if rc != 0:
            print("nmap scan failed: {0}".format(nmproc.stderr))
            # print(type(nmproc.stdout))
        try:
            parsed = NmapParser.parse(nmproc.stdout)
        except NmapParserException as e:
            print("Exception raised while parsing scan: {0}".format(e.msg))
        return parsed


def print_scan(nmap_report):
    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames[0]
        else:
            tmp_host = host.address

        if host.is_up():
            print("Nmap scan report for {0} ({1})".format(tmp_host,
                                                          host.address))
            print("Host is {0}.".format(host.status))
            if host.vendor:
                print("Vendor is {0}.".format(host.vendor))


def get_ips_from_scan(nmap_report):
    for host in nmap_report.hosts:
        if len(host.hostnames):
            tmp_host = host.hostnames[0]
        else:
            tmp_host = host.address

        if host.is_up():
            # ips.append("{0} {1} {2}".format(host.address, tmp_host,
            #                                 host.vendor))
            tmp_val = "{0} {1} {2}".format(host.address, tmp_host, host.vendor)
            if tmp_val not in ips:
                ips.append(tmp_val)


def add_hosts_to_list(nmap_report, ip_list):
    for host in nmap_report.hosts:
        if host.is_up():
            ip_list.append(host)


class Threaded_detailed_scan(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        # run a detailed scan on each ip in the ips list
        self.run_scan()
        self.print_detailed_scans()
        self.queue.put("detailed scan finished")

    def run_scan(self):
        for ip in ips:
            parsed = None
            target = ip.address
            print("performing detailed scan for {0}".format(target))
            nmproc = NmapProcess(target, "-A")
            rc = nmproc.run()
            if rc != 0:
                print("nmap scan failed: {0}".format(nmproc.stderr))
                # print(type(nmproc.stdout))
            try:
                parsed = NmapParser.parse(nmproc.stdout)
            except NmapParserException as e:
                print("Exception raised while parsing scan: {0}".format(e.msg))
            detailed_ips[target] = parsed

    def print_detailed_scans(self):
        for ip, report in detailed_ips.items():
            for host in report.hosts:
                if len(host.hostnames):
                    tmp_host = host.hostnames[0]
                else:
                    tmp_host = host.address
                if host.is_up():
                    print("Detailed report for {0} ({1})".format(tmp_host,
                                                                 host.address))
                    print("Vendor is {0}".format(host.vendor))
                    for serv in host.services:
                        pserv = "{0:>5s}/{1:3s}  {2:12s}  {3}".format(
                                str(serv.port),
                                serv.protocol,
                                serv.state,
                                serv.service)
                        if len(serv.banner):
                            pserv += " ({0})".format(serv.banner)
                        print(pserv)


def download_vulnerability_list():
    # method to download the mitre cve file
    # check if the file needs updating first
    last_updated = ""
    # read the last time list was updated from file
    try:
        with open("last_updated.txt", 'r') as update_file:
            last_updated = update_file.read()
            print(last_updated)
    except IOError:  # if the file doesn't exist it has never been updated
        # so set the last updated date to 0 to force a download
        print("Never Downloaded Vulnerability list")
        last_updated = "0"

    index_url = "https://cve.mitre.org/data/downloads/index.html"
    # check the index of the mitre list to see when it was last generated
    check_page = urllib.request.urlopen(index_url).read().decode("utf8")
    try:
        last_generated = re.search(
            'CVE downloads data last generated:\\n(.+?)\n\n',
            check_page).group(1)
    except AttributeError:
        last_generated = "0"  # if for some reason it is not available set this
        # to 0 so that it does not attempt a download
    print(last_generated)
    last_generated = last_generated.replace("-", "")
    print(last_generated)
    # if it has been generated since it was last updated then download it
    if int(last_updated) < int(last_generated):
        print("Downloading latest vulnerability data")
        vul_url = "https://cve.mitre.org/data/downloads/allitems.csv"
        with urllib.request.urlopen(vul_url) as response, \
                open("Mitre_CVE_database.csv", 'wb') as out_file:
                data = response.read()
                out_file.write(data)
        with open("last_updated.txt", 'w') as update_file:
            update_file.write(last_generated)
    else:
        print("Vulnerability data already up to date")


root = Tk()
my_gui = scan_GUI(root)
root.mainloop()
