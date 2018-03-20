from tkinter import Tk, Label, Button, StringVar, Listbox
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
# import subprocess
import socket
import threading
import queue
# import xml.etree.ElementTree as ET

ips = []
devices = []


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
        self.ipList = Listbox(master, width=100)
        self.ipList.pack()

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

    def process_queue(self):
        try:
            msg = self.queue.get(0)
            print(msg)
            self.scanrunning = 0
            self.scanvar.set("Scan finished")
            tmpcount = 0
            self.ipList.delete(0, self.ipList.size())
            for ip in ips:
                self.ipList.insert(tmpcount, ip)
                tmpcount += 1
        except queue.Empty:
            self.master.after(100, self.process_queue)


class ThreadedScan(threading.Thread):  # class for intial ip scan
    def __init__(self, queue, localIP):
        threading.Thread.__init__(self)
        self.queue = queue
        self.localIP = localIP

    def run(self):
        # run an nmap scan outputting result to a file, put task finished to
        # queue when it ends
        report = run_scan(self.localIP)
        if report:
            print_scan(report)
            get_ips_from_scan(report)
        else:
            print("No results returned")
        self.queue.put("Task finished")


def run_scan(IP):
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
    str1 = "192.168.1.81 amazon-fe4b4ee6c.home Amazon Technologies"
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


class Threaded_device_scan(threading.Thread):
    def __init__(self, queue, dev_ip):
        threading.Thread.__init__(self)
        self.queue = queue
        self.dev_ip = dev_ip


root = Tk()
my_gui = scan_GUI(root)
root.mainloop()
