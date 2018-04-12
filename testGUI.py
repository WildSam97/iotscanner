# GUI imports
import tkinter as tk
from tkinter.font import Font
from tkinter import ttk as ttk
# other imports
import socket
import queue
import threading
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

ips = []
initial_scan_results = {}


class main_GUI:
    def __init__(self, master):
        # varible to toggle if a scan is running
        self.scan_running = 0
        self.master = master
        # title of window
        master.title("IoT device Scanner")
        # main frame to hold all other items
        self.main_frame = tk.Frame(root)
        self.main_frame.pack()
        # title label
        title_font = Font(family="Helvetica", size=36, weight="bold")
        self.title_label = tk.Label(self.main_frame,
                                    text="IoT Scanner",
                                    font=title_font)
        self.title_label.grid(row=0, column=1, sticky='WE')
        # scan frame, holds info about scan in progress
        self.scan_frame = tk.Frame(self.main_frame,
                                   padx=5,
                                   pady=5,
                                   borderwidth=2,
                                   relief='groove')
        self.scan_frame.grid(row=1, column=1)
        # frame for general info
        self.info_frame = tk.Frame(self.scan_frame,
                                   padx=5,
                                   pady=5,
                                   borderwidth=2)
        self.info_frame.grid(row=0, column=0)
        # last scan date label & variable
        self.last_scan_var = tk.StringVar()
        self.last_scan_var.set("Last scan date: Never")
        self.last_scan_label = tk.Label(self.info_frame,
                                        textvariable=self.last_scan_var)
        self.last_scan_label.grid(row=0, column=0, padx=2, pady=2)
        # label for this device's ip address
        self.my_ip_var = tk.StringVar()
        self.my_ip_var.set("This machine's IP: Scan not run")
        self.my_ip_label = tk.Label(self.info_frame,
                                    textvariable=self.my_ip_var)
        self.my_ip_label.grid(row=1, column=0, padx=2, pady=2)
        # button to run a new scan
        self.scan_button = tk.Button(self.scan_frame,
                                     text="Run Scan",
                                     command=self.start_scan)
        self.scan_button.grid(row=0, column=2, padx=2, pady=2)
        # frame for scan progress stuff
        self.progress_frame = tk.Frame(self.scan_frame)
        self.progress_frame.grid(row=0, column=1, padx=2, pady=2)
        # progress bar for scan
        self.scan_progress = ttk.Progressbar(self.progress_frame,
                                             length=200)
        self.scan_progress.grid(row=0, padx=2, pady=2)
        # status label for scan
        self.status_var = tk.StringVar()
        self.status_var.set("Scan not currently running")
        self.status_label = tk.Label(self.progress_frame,
                                     textvariable=self.status_var)
        self.status_label.grid(row=1, padx=2, pady=2)
        # frame for scroll and devices
        self.scroll_devices_frame = tk.Frame(self.main_frame)
        self.scroll_devices_frame.grid(row=2, column=1, padx=2, pady=2,
                                       sticky='NSWE')
        # devices_frame title
        self.scroll_title = tk.Label(self.scroll_devices_frame,
                                     text="Device List")
        self.scroll_title.grid(row=0, column=0, sticky='WE')
        # frame for device info
        self.devices_frame = tk.Frame(self.scroll_devices_frame)
        self.devices_frame.grid(row=1, column=0, sticky='WE')
        # list of devices (device frames)
        self.device_list = []
        # frame for the scroll buttons
        self.scroll_frame = tk.Frame(self.scroll_devices_frame)
        self.scroll_frame.grid(row=1, column=1, sticky='NSE')
        # scroll up
        self.scroll_up_button = tk.Button(
            self.scroll_frame,
            text="^",
            command=lambda: self.scroll_devices(1))
        self.scroll_up_button.pack(side=tk.TOP)
        # scroll down
        self.scroll_down_button = tk.Button(
            self.scroll_frame,
            text="v",
            command=lambda: self.scroll_devices(-1))
        self.scroll_down_button.pack(side=tk.BOTTOM)
        # side button frame for navigation
        self.side_button_frame = tk.Frame(self.main_frame)
        self.side_button_frame.grid(row=2, column=0, sticky='NS')
        # home button
        self.home_button = tk.Button(
            self.side_button_frame,
            text="Home",
            command=lambda: self.switch_frames(
             self.scroll_devices_frame
            ))
        self.home_button.grid(row=0, sticky='NEW')
        # search vulnerabilites button
        self.search_button = tk.Button(self.side_button_frame,
                                       text="Search vulnerabilites",
                                       command=lambda: self.switch_frames(
                                        self.search_frame.search_frame
                                       ))
        self.search_button.grid(row=2, sticky='NEW')
        # password checker button
        self.password_button = tk.Button(self.side_button_frame,
                                         text="Check password strength",
                                         command=lambda: self.switch_frames(
                                          self.password_frame.password_frame
                                         ))
        self.password_button.grid(row=3, sticky='NEW')
        # frame for searching CVEs
        self.search_frame = search_frame(self.main_frame)
        # frame for password checker
        self.password_frame = password_frame(self.main_frame)
        # dummy frame for detailed view (in case nav used before scan is run)
        self.scan_details_frame = details_frame(self.main_frame, 0)

        # add a bunch of test devices
        # for i in range(0, 15):
        #     self.device_list.append(
        #         device_frame(
        #             self.devices_frame,
        #             self,
        #            i,
        #            "192.168.0.{0}".format(i),
        #            "Seiko Epson",
        #            "A printer",
        #            2,
        #            5))
    # end of __init__ function

    # method to scroll/cycle through the devices in the device list
    def scroll_devices(self, amount):
        # check if we need to scroll
        canscroll = 0
        for device in self.device_list:
            if ((device.index < 0 and amount > 0)
               or (device.index > 5 and amount < 0)):
                    canscroll = 1
        # if we do then scroll
        if canscroll == 1:
            for device in self.device_list:
                device.index = device.index + amount
                if device.index < 0 or device.index > 5:
                    device.dev_frame.grid_forget()
                else:
                    device.dev_frame.grid(row=device.index)
    # end of scroll_devices method

    # function to switch the main frame being displayed
    def switch_frames(self, new_frame):
        self.password_frame.password_frame.grid_forget()
        self.search_frame.search_frame.grid_forget()
        self.scroll_devices_frame.grid_forget()
        self.scan_details_frame.details_frame.grid_forget()
        new_frame.grid(
            row=2,
            column=1,
            padx=2,
            pady=2)
    # end of switch_frames function

    # function for start scan button
    def start_scan(self):
            # set the status bar to show a scan is running
            self.status_var.set("Inital scan running")
            # disable to scan button so the user can't start another one
            self.scan_button['state'] = "disabled"
            # use google dns and sockets to find ip of current device
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 53))
            localIP = s.getsockname()[0]
            self.my_ip_var.set("This machine's IP: {0}".format(localIP))
            # append /24 to scan subnet device in on
            self.target_range = localIP + '/24'
            # queue for messages from other threads
            self.queue = queue.Queue()
            # counter for initial scan passes
            self.num_scans = 0
            # start initial scan
            threaded_initial_scan(self.queue, self.target_range).start()
            self.master.after(100, self.process_queue)
    # end of start scan function

    # function to process queue of events from other threads
    def process_queue(self):
        try:
            # get the latest message from the queue
            msg = self.queue.get(0)
            print(msg)
            if msg == "Initial scan finished":
                # update progress status and bar
                self.num_scans += 1
                text = "Initial scan {0} finished".format(self.num_scans)
                self.status_var.set(text)
                self.scan_progress.step(10)
                if self.num_scans < 3:
                    threaded_initial_scan(self.queue,
                                          self.target_range).start()
                    self.master.after(100, self.process_queue)
                elif self.num_scans == 3:
                    self.display_initial_results()
                    self.status_var.set(
                        "Initial scans finished - starting detailed scans")
                    self.num_detailed_scans = 0
                    # start a detailed scan for each device
                    print("starting detailed scans")
                #    for ip, host in initial_scan_results.items():
                #        if host.is_up():
                #            threaded_detailed_scan(self.queue, ip).start()
                    threaded_detailed_scan(self.queue, ips[0]).start()
                    self.master.after(100, self.process_queue)
            elif msg == "detailed scan finished":
                self.num_detailed_scans += 1
                text = "{0}/{1} detailed scans complete".format(
                    self.num_detailed_scans, len(initial_scan_results.keys()))
                self.status_var.set(text)
                if self.num_detailed_scans == len(initial_scan_results.keys()):
                    self.status_var.set("Detailed scans complete")
                else:
                    threaded_detailed_scan(
                        self.queue,
                        ips[self.num_detailed_scans]).start()
                self.master.after(100, self.process_queue)
        except queue.Empty:
            self.master.after(100, self.process_queue)
    # end of process_queue function

    # function to display initial scan results on gui
    def display_initial_results(self):
        print("Adding intial results to gui")
        for ip, host in initial_scan_results.items():
            if len(host.hostnames):
                tmp_host = host.hostnames[0]
            else:
                tmp_host = host.address
            if host.is_up():
                self.device_list.append(
                    device_frame(
                        self.devices_frame,
                        self,
                        len(self.device_list),
                        host.address,
                        host.vendor,
                        tmp_host,
                        "-",
                        "-"))
    # end of display initial results function

# end of main_GUI class


# class for frame that contains info for specific device
class device_frame:
    def __init__(self, master, container, index, dev_ip, dev_vendor,
                 dev_name, dev_vuln, dev_ports):
        self.master = master
        self.container = container
        self.index = index  # index relative to the grid
        # name of the device (can be edited by user)
        self.device_name = tk.StringVar()
        self.device_name.set(dev_name)
        # ip address of device (for passing device to other functions)
        self.ip_address = dev_ip
        # frame to hold this device
        self.dev_frame = tk.Frame(self.master,
                                  padx=5,
                                  pady=5,
                                  borderwidth=2,
                                  relief="groove")
        # only add first few devices to the grid
        if self.index >= 0 and self.index <= 5:
            self.dev_frame.grid(row=self.index)
        # ip address Label
        self.dev_ip_label = tk.Label(self.dev_frame,
                                     text="IP Address: {0}".format(dev_ip),
                                     width=40,
                                     anchor='w')
        self.dev_ip_label.grid(row=0, column=0, padx=2, pady=2, sticky=tk.W)
        # vendor Label
        self.vendor_label = tk.Label(self.dev_frame,
                                     text="Vendor: {0}".format(dev_vendor),
                                     width=40,
                                     anchor='w')
        self.vendor_label.grid(row=1, column=0, padx=2, pady=2, sticky=tk.W)
        # label to present name
        self.device_name_label = tk.Label(
            self.dev_frame,
            text="Device Name: {0}".format(self.device_name.get()),
            width=40,
            anchor='w')
        self.device_name_label.grid(
            row=2, column=0, padx=2, pady=2, sticky=tk.W)
        # button to edit device name
        self.device_name_button = tk.Button(self.dev_frame,
                                            text="Edit device name",
                                            command=self.edit_device_name
                                            )
        self.device_name_button.grid(row=0,
                                     column=3, padx=2, pady=2, sticky=tk.E)
        # entry for user to set device name
        self.device_name_entry = tk.Entry(self.dev_frame,
                                          textvariable=self.device_name,
                                          width=40)
        # save changes buttons
        self.save_changes_button = tk.Button(
            self.dev_frame,
            text="Save changes",
            command=self.save_device_name)
        # cancel changes button
        self.cancel_changes_button = tk.Button(self.dev_frame,
                                               text="Cancel changes",
                                               command=self.cancel_device_name)
        # open port Label
        self.port_label = tk.Label(self.dev_frame,
                                   text="Open ports: {0}".format(dev_ports))
        self.port_label.grid(row=0, column=2, sticky=tk.W)
        # potential vulnerabilities Label
        self.vuln_label = tk.Label(
            self.dev_frame,
            text="Potential vulnerabilities: {0}".format(dev_vuln))
        self.vuln_label.grid(row=1, column=2, padx=2, pady=2, sticky=tk.W)
        # show details button
        self.details_button = tk.Button(
            self.dev_frame,
            text="Show Details",
            command=self.show_details)
        self.details_button.grid(row=2, column=3, padx=2, pady=2, sticky=tk.E)
    # end of __init__ function

    # function to edit device name
    def edit_device_name(self):
        # hide the name and edit buttons
        self.device_name_label.grid_forget()
        self.device_name_button.grid_forget()
        # show entry, save and cancel buttons
        self.cancel_changes_button.grid(
            row=1, column=3, padx=2, pady=2, sticky=tk.E)
        self.save_changes_button.grid(
            row=0, column=3, padx=2, pady=2, sticky=tk.E)
        self.device_name_entry.grid(
            row=2, column=0, padx=2, pady=2, sticky=tk.W)
        # tempory name in case the change isn't saved
        self.tempName = self.device_name.get()
    # end of edit_device_name function

    # function to save change to device name
    def save_device_name(self):
        self.device_name_label['text'] = "Device Name: {0}".format(
                                                    self.device_name.get())
        # hide cancel, save and entry
        self.cancel_changes_button.grid_forget()
        self.save_changes_button.grid_forget()
        self.device_name_entry.grid_forget()
        # show device name label and edit button
        self.device_name_label.grid(
            row=2, column=0, padx=2, pady=2, sticky=tk.W)
        self.device_name_button.grid(row=0,
                                     column=3, padx=2, pady=2, sticky=tk.E)
    # end of save_device_name function

    # function to cancel changes to device name
    def cancel_device_name(self):
        # hide cancel, save and entry
        self.cancel_changes_button.grid_forget()
        self.save_changes_button.grid_forget()
        self.device_name_entry.grid_forget()
        # set the device name back to the old value from tempory
        self.device_name.set(self.tempName)
        # show device name label and edit button
        self.device_name_label.grid(
            row=2, column=0, padx=2, pady=2, sticky=tk.W)
        self.device_name_button.grid(row=0,
                                     column=3, padx=2, pady=2, sticky=tk.E)
    # end of cancel_device_name function

    # function to show details for a device
    def show_details(self):
        self.container.scroll_devices_frame.grid_forget()
        self.container.scan_details_frame = details_frame(
            self.container.main_frame,
            self.ip_address)
        self.container.scan_details_frame.details_frame.grid(
            row=2,
            column=1,
            padx=2,
            pady=2)
        # end of show_details function

# end of device_frame class


# class for frame to hold detailed report of a specific device
class details_frame:
        def __init__(self, master, ip_address):
            self.master = master
            # frame to hold everything
            self.details_frame = tk.Frame(master)
            # title label frame
            self.title_label = tk.Label(
                self.details_frame,
                text="Detailed Report for {0}".format(ip_address))
            self.title_label.pack(side='top')
        # end of __init__ function
# end of details_frame class


# class for frame to allow searching of CVE vulnerabilities
class search_frame:
    def __init__(self, master):
        self.master = master
        # frame to hold everything
        self.search_frame = tk.Frame(master)
        # title label
        self.title_label = tk.Label(self.search_frame,
                                    text="Search for vulnerabilites")
        self.title_label.pack(side='top')
    # end of __init__ function
# end of search_frame class


# class for frame to allow testing of passwords
class password_frame:
    def __init__(self, master):
        self.master = master
        # frame to hold everything
        self.password_frame = tk.Frame(master)
        # title label
        self.title_label = tk.Label(self.password_frame,
                                    text="Password Checker")
        self.title_label.pack(side='top')
    # end of __init__ function
# end of password_frame class


# threaded class for initial scan (device detection)
class threaded_initial_scan(threading.Thread):
    def __init__(self, queue, localIP):
        threading.Thread.__init__(self)
        self.queue = queue
        self.localIP = localIP
        print("Starting initial scan")
    # end of __init__ function

    # main function called when thread is started
    def run(self):
        # run a basic nmap scan to discover devices
        report = self.run_scan(self.localIP)
        if report:
            # debug print report
            print_scan(report)
            # add report contents to the results if not already there
            for host in report.hosts:
                if host.address not in ips and host.is_up():
                    initial_scan_results[host.address] = host
                    ips.append(host.address)
        # add message to queue to state that initial scan is done
        self.queue.put("Initial scan finished")
    # end of run function

    # function to run the scan
    def run_scan(self, IP):
        parsed = None
        nmproc = NmapProcess(IP, "-sP")
        rc = nmproc.run()
        if rc != 0:
            print("nmap scan failed: {0}".format(nmproc.stderr))
        try:
            parsed = NmapParser.parse(nmproc.stdout)
        except NmapParserException as e:
            print("Exception raised while parsing scan: {0}". format(e.msg))
        return parsed
    # end of run_scan function
# end of threaded_initial_scan class


# threaded class for detailed scans (open port & OS detection)
class threaded_detailed_scan(threading.Thread):
    def __init__(self, queue, target_ip):
        threading.Thread.__init__(self)
        self.queue = queue
        self.target_ip = target_ip
        print("performing detailed scan for {0}".format(self.target_ip))
    # end of __init__ function

    def run(self):
        print("run for {0}".format(self.target_ip))
        report = self.run_scan(self.target_ip)
        if report:
            print_scan(report)
        self.queue.put("detailed scan finished")
    # end of run function

    def run_scan(self, IP):
        print("scanning for {0}".format(IP))
        parsed = None
        nmproc = NmapProcess(IP, "-A", "-Pn")
        rc = nmproc.run()
        if rc != 0:
            print("nmap scan failed: {0}".format(nmproc.stderr))
        try:
            parsed = NmapParser.parse(nmproc.stdout)
        except NmapParserException as e:
            print("Exception raised while parsing scan: {0}".format(e.msg))
        return parsed
    # end of run_scan function

# end of threaded_detailed_scan class


# function to print out scan results to console (used for debug)
def print_scan(nmap_report):
    # loop through each host, print out basic info for host
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


root = tk.Tk()
my_gui = main_GUI(root)
root.mainloop()
