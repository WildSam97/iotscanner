from tkinter import Tk, Label, Button, StringVar
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
# import subprocess
import socket
import threading
import queue
# import xml.etree.ElementTree as ET


class scanGUI():

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
            self.scanrunning = 0
            print(msg)
            self.scanvar.set("Scan finished")
        except queue.Empty:
            self.master.after(100, self.process_queue)


class ThreadedScan(threading.Thread):
    def __init__(self, queue, localIP):
        threading.Thread.__init__(self)
        self.queue = queue
        self.localIP = localIP

    def run(self):
        # run an nmap scan outputting result to a file, put task finished to
        # queue when it ends
        # rewrite this using libnmap
        # subprocess.run(["nmap", "-sP", "-PU161,5353", "-PA21,22,25,3389",
        #               "-PS22,3389", "-oA", "pythontestscanresult",
        #                self.localIP])

        # tree = ET.parse('pythontestscanresult.xml')
        # root = tree.getroot()
        # for host in root.iter('host'):
        #     print(host.attrib)
        report = run_scan(self.localIP)
        if report:
            print_scan(report)
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
            tmp_host = host.hostnames.pop()
        else:
            tmp_host = host.address

        if host.is_up():
            print("Nmap scan report for {0} ({1})".format(tmp_host,
                                                          host.address))
            print("Host is {0}.".format(host.status))
            if host.vendor:
                print("Vendor is {0}.".format(host.vendor))


root = Tk()
my_gui = scanGUI(root)
root.mainloop()
