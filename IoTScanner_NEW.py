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
import urllib.request
import re
from datetime import date
import csv
import webbrowser

ips = []
initial_scan_results = {}
detailed_scan_results = {}
vulnerability_dict = {}


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
        self.status_var.set("Setting up...")
        self.status_label = tk.Label(self.progress_frame,
                                     textvariable=self.status_var)
        self.status_label.grid(row=1, padx=2, pady=2)
        # frame for scroll and devices
        self.scroll_devices_frame = tk.Frame(self.main_frame)
        # devices_frame title
        self.scroll_title = tk.Label(self.scroll_devices_frame,
                                     text="Device List")
        self.scroll_title.grid(row=0, column=0, sticky='WE')
        # frame for device info
        self.devices_frame = tk.Frame(self.scroll_devices_frame)
        self.devices_frame.grid(row=1, column=0, sticky='WE')
        # list of devices (device frames)
        self.device_list = {}
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
        self.scan_details_frame = details_frame(self.main_frame, "", "", "")
        # check when last scan was ran
        self.last_run()
        # check if vulnerability databases need updating
        self.master.after(100, self.check_updates)
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
        for ip, device in self.device_list.items():
            if ((device.index < 0 and amount > 0)
               or (device.index > 5 and amount < 0)):
                    canscroll = 1
        # if we do then scroll
        if canscroll == 1:
            for ip, device in self.device_list.items():
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
        if len(self.device_list.keys()) == 0:
            self.scroll_devices_frame.grid_forget()
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
            # stage 1 - initial scans
            if msg == "Initial scan finished":
                # update progress status and bar
                self.num_scans += 1
                text = "Initial scan {0} finished".format(self.num_scans)
                self.status_var.set(text)
                self.scan_progress.step(10)
                # if less than 3 scans carried out do another one
                # this increases chance a device is detected
                if self.num_scans < 3:
                    threaded_initial_scan(self.queue,
                                          self.target_range).start()
                    self.master.after(100, self.process_queue)
                # if 3 scans have been carried out start the detailed scans
                elif self.num_scans == 3:
                    self.display_initial_results()
                    self.status_var.set(
                        "Initial scans finished - starting detailed scans")
                    self.num_detailed_scans = 0
                    # start a detailed scan for 1st device in list
                    print("starting detailed scans")
                    threaded_detailed_scan(self.queue, ips[0]).start()
                    self.master.after(100, self.process_queue)
            # when a detailed scan is finished
            elif msg == "detailed scan finished":
                self.display_detailed_results(ips[self.num_detailed_scans])
                self.num_detailed_scans += 1
                self.scan_progress.step(
                    (70 * (1/len(initial_scan_results.keys()))))
                text = "{0}/{1} detailed scans complete".format(
                    self.num_detailed_scans, len(initial_scan_results.keys()))
                self.status_var.set(text)
                # if all detailed scans are done scan is finished
                if self.num_detailed_scans == len(initial_scan_results.keys()):
                    self.status_var.set("Scan complete")
                    self.scan_button['state'] = "normal"
                    today = str(date.today())
                    with open("last_scan.txt", 'w') as update_file:
                        update_file.write(today)
                    self.last_scan_var.set("Last Scan date: {0}".format(today))
                    # print("Starting vulnerability detection")
                # otherwise start the scan for the next device in the list
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
        self.scroll_devices_frame.grid(row=2, column=1, padx=2, pady=2,
                                       sticky='NSWE')
        for ip, host in initial_scan_results.items():
            if len(host.hostnames):
                tmp_host = host.hostnames[0]
            else:
                tmp_host = host.address
            if host.is_up():
                # self.device_list.append(
                tmp_device = device_frame(
                        self.devices_frame,
                        self,
                        len(self.device_list.keys()),
                        host.address,
                        host.vendor,
                        tmp_host,
                        "-",
                        "-",
                        "-")
                self.device_list[host.address] = tmp_device
    # end of display initial results function

    # function to add detailed scan info to display
    def display_detailed_results(self, device_ip):
        print("adding detailed info to gui")
        host = detailed_scan_results[device_ip]
        dev_frame = self.device_list[host.address]
        port_count = len(host.get_open_ports())
        dev_frame.port_label['text'] = "Open ports: {0}".format(port_count)
        try:
            dev_frame.OS_label['text'] = "Operating System: {0}".format(
                host.os_match_probabilities()[0].name
            )
            dev_frame.os_name.set(host.os_match_probabilities()[0].name)
        except Exception:
            dev_frame.OS_label['text'] = "Operating System: unknown"
            dev_frame.os_name.set("unknown")
        dev_frame.vuln_label['text'] = "Potential Vulnerabilities: {0}".format(
            len(vulnerability_dict[host.address]))
    # end of display_detailed_results function

    # function to check when last scan was carried out
    def last_run(self):
        self.last_scan = ""

        try:
            with open("last_scan.txt", 'r') as update_file:
                self.last_scan = update_file.read()
                print(self.last_scan)
                self.last_scan_var.set(
                    "Last scan date: {0}".format(self.last_scan))
        except IOError:  # if the file doesn't exist it has never been updated
            # so set the last updated date to 0 to force a download
            print("Never carried out a scan")
    # end of last_run function

    # function to check if vulnerability list needs updating and download
    def check_updates(self):
        print("Checking for updates")
        try:
            with open("last_updated.txt", 'r') as update_file:
                self.last_updated = update_file.read()
                print(self.last_updated)
        except IOError:
            print("never downloaded")
            self.last_updated = ""
        index_url = "https://cve.mitre.org/data/downloads/index.html"
        # check the index of the mitre list to see when it was last generated
        check_page = urllib.request.urlopen(index_url).read().decode("utf8")
        try:
            last_generated = re.search(
                'CVE downloads data last generated:\n(.+?)\n\n',
                check_page).group(1)
        except AttributeError:
            last_generated = "0"  # if for some reason it is not available set
            # to 0 so that it does not attempt a download
        print(last_generated)
        tmp_last_updated = self.last_updated.replace("-", "")
        tmp_last_generated = last_generated.replace("-", "")
        if tmp_last_updated < tmp_last_generated:
            print("Downloading latest vulnerability data")
            self.status_var.set("Downloading CVE List")
            root.update()
            vul_url = "https://cve.mitre.org/data/downloads/allitems.csv"
            with urllib.request.urlopen(vul_url) as response, \
                    open("Mitre_CVE_database.csv", 'wb') as out_file:
                    data = response.read()
                    out_file.write(data)
            print("Download finished")
        else:
            print("Vulnerability data already up to date")
        # check when password list was last updated and download if needed
        index_url = "https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"  # noqa
        check_page = urllib.request.urlopen(index_url).read().decode("utf8")
        try:
            last_generated = re.search(
                '<relative-time datetime="(.+?)T', check_page).group(1)
        except AttributeError:
            # if for some reason it is not available set
            # to 0 so that it does not attempt a download
            last_generated = "0"
        print(last_generated)
        tmp_last_updated = self.last_updated.replace("-", "")
        tmp_last_generated = last_generated.replace("-", "")
        if tmp_last_updated < tmp_last_generated:
            print("Downloading top-1000000 password list")
            self.status_var.set("Downloading password list")
            root.update()
            pw_url = "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"  # noqa
            with urllib.request.urlopen(pw_url) as response, \
                    open("top_10_million_top_1_mil.txt", 'wb') as out_file:
                    data = response.read()
                    out_file.write(data)
            print("Download Finished")
        else:
            print("Top 10 mil top 1 mil up to date")
        # exploit db is updated daily so check if already downloaded today
        # if not download it
        last_generated = str(date.today())
        tmp_last_updated = self.last_updated.replace("-", "")
        tmp_last_generated = last_generated.replace("-", "")
        if tmp_last_updated < tmp_last_generated:
            print("Downloading exploit db list")
            self.status_var.set("Downloading exploit db list")
            root.update()
            db_url = "https://raw.githubusercontent.com/offensive-security/exploit-database/master/files_exploits.csv"  # noqa
            with urllib.request.urlopen(db_url) as response, \
                    open("exploitdb.csv", 'wb') as out_file:
                    data = response.read()
                    out_file.write(data)
            print("Download finished")
        else:
            print("Exploit db up to date")
        # update last_updated file with todays date.
        today = str(date.today())
        with open("last_updated.txt", 'w') as update_file:
            update_file.write(today)
        self.status_var.set("Ready to Scan")
        # use exploit db as well?
        # https://github.com/offensive-security/exploit-database/raw/master/files_exploits.csv
    # end of check_updates function

    # function to update last run date to today
    def update_last_run(self):
        print("updating last run date")
        today = str(date.today())
        with open("last_scan.txt", 'w') as update_file:
            update_file.write(today)
        self.last_scan_var.set("Last scan date: {0}".format(today))
    # end of update_last_run function
# end of main_GUI class


# class for frame that contains info for specific device
class device_frame:
    def __init__(self, master, container, index, dev_ip, dev_vendor,
                 dev_name, dev_vuln, dev_ports, os):
        self.master = master
        self.container = container
        self.index = index  # index relative to the grid
        # name of the device (can be edited by user)
        self.device_name = tk.StringVar()
        self.device_name.set(dev_name)
        # operating system name (can be changed by user)
        self.os_name = tk.StringVar()
        self.os_name.set(os)
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
                                            text="Edit device details",
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
        # OS Label
        self.OS_label = tk.Label(self.dev_frame,
                                 text="Operating System: {0}".format(os),
                                 width=100,
                                 anchor='w')
        self.OS_label.grid(row=2, column=2, padx=2, pady=2, sticky='W')
        # entry for user to set os
        self.OS_entry = tk.Entry(self.dev_frame,
                                 textvariable=self.os_name,
                                 width=100)
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
        self.OS_label.grid_forget()
        # show entry, save and cancel buttons
        self.cancel_changes_button.grid(
            row=1, column=3, padx=2, pady=2, sticky=tk.E)
        self.save_changes_button.grid(
            row=0, column=3, padx=2, pady=2, sticky=tk.E)
        self.device_name_entry.grid(
            row=2, column=0, padx=2, pady=2, sticky=tk.W)
        self.OS_entry.grid(
            row=2, column=2, padx=2, pady=2, sticky=tk.W)
        # tempory name in case the change isn't saved
        self.tempName = self.device_name.get()
        self.tempOS = self.os_name.get()
    # end of edit_device_name function

    # function to save change to device name
    def save_device_name(self):
        self.device_name_label['text'] = "Device Name: {0}".format(
                                                    self.device_name.get())
        self.OS_label['text'] = "Operating System: {0}".format(
                                                    self.os_name.get())
        # hide cancel, save and entry
        self.cancel_changes_button.grid_forget()
        self.save_changes_button.grid_forget()
        self.device_name_entry.grid_forget()
        self.OS_entry.grid_forget()
        # show device name label and edit button
        self.device_name_label.grid(
            row=2, column=0, padx=2, pady=2, sticky=tk.W)
        self.device_name_button.grid(row=0,
                                     column=3, padx=2, pady=2, sticky=tk.E)
        self.OS_label.grid(row=2, column=2, padx=2, pady=2, sticky='W')
        # lookup vulnerabilities for this device as name and os is changed
        find_device_vulnerabilities(
            detailed_scan_results[self.ip_address],
            self.os_name.get(),
            self.device_name.get())
    # end of save_device_name function

    # function to cancel changes to device name
    def cancel_device_name(self):
        # hide cancel, save and entry
        self.cancel_changes_button.grid_forget()
        self.save_changes_button.grid_forget()
        self.device_name_entry.grid_forget()
        self.OS_entry.grid_forget()
        # set the device name back to the old value from tempory
        self.device_name.set(self.tempName)
        self.os_name.set(self.tempOS)
        # show device name label and edit button
        self.device_name_label.grid(
            row=2, column=0, padx=2, pady=2, sticky=tk.W)
        self.device_name_button.grid(row=0,
                                     column=3, padx=2, pady=2, sticky=tk.E)
        self.OS_label.grid(row=2, column=2, padx=2, pady=2, sticky='W')
    # end of cancel_device_name function

    # function to show details for a device
    def show_details(self):
        self.container.scroll_devices_frame.grid_forget()
        self.container.scan_details_frame = details_frame(
            self.container.main_frame,
            self.ip_address,
            self.device_name.get(),
            self.os_name.get())
        self.container.scan_details_frame.details_frame.grid(
            row=2,
            column=1,
            padx=2,
            pady=2)
        # end of show_details function

# end of device_frame class


# class for frame to hold detailed report of a specific device
class details_frame:
    def __init__(self, master, ip_address, dev_name, dev_os):
        self.master = master
        self.ip_address = ip_address
        self.dev_name = dev_name
        self.dev_os = dev_os
        # frame to hold everything
        self.details_frame = tk.Frame(master)
        # device
        if ip_address not in detailed_scan_results.keys():
            return
        self.device = detailed_scan_results[ip_address]
        # title label frame
        self.title_label = tk.Label(
            self.details_frame,
            text="Detailed Report for {0}".format(self.ip_address))
        self.title_label.grid(row=0, column=0, sticky='W')
        # upper frame
        self.header_frame = tk.Frame(self.details_frame)
        self.header_frame.grid(row=1, column=0, sticky='WE')
        # label for vendor
        self.dev_vendor_label = tk.Label(self.header_frame,
                                         text="Vendor: {0}".format(
                                            self.device.vendor),
                                         anchor='w')
        self.dev_vendor_label.grid(row=0, column=0, sticky='W')
        # label for device name
        self.dev_name_label = tk.Label(self.header_frame,
                                       text="Device name: {0}".format(
                                        self.dev_name),
                                       anchor='w')
        self.dev_name_label.grid(row=0, column=1, sticky='W')
        # label for OS
        self.os_name_label = tk.Label(self.header_frame,
                                      text="Operating System: {0}".format(
                                        self.dev_os),
                                      anchor='w')
        self.os_name_label.grid(row=1, column=0, sticky='W')
        # frame for services
        self.service_frame = tk.Frame(self.details_frame)
        self.service_frame.grid(row=2, column=0, sticky='WE')
        # label for open ports
        self.service_label = tk.Label(
            self.service_frame,
            text="{0} services running on open ports:".format(
                len(self.device.get_open_ports())),
            anchor='w')
        self.service_label.grid(row=0, column=0, sticky='W')
        # frame for scrollbar and list box
        self.list_frame = tk.Frame(self.service_frame)
        self.list_frame.grid(row=1, column=0)
        # scrollbar for list box
        self.list_scroll = tk.Scrollbar(self.list_frame)
        self.list_scroll.grid(row=0, column=1, sticky='NSEW')
        # general fix suggestion label
        self.general_label = tk.Label(self.service_frame)
        self.general_label.grid(row=1, column=1)
        self.general_fix_text = "General Fixes: \n"
        # listbox for services on open ports
        self.service_list = tk.Listbox(
            self.list_frame,
            height=10,
            width=40,
            yscrollcommand=self.list_scroll.set)
        self.service_list.grid(row=0, column=0, sticky='NSEW')
        # loop through services, add each to listbox
        self.service_list.insert(0, "PORT      SERVICE")
        for service in self.device.services:
            if service.state != "open":
                continue
            else:
                text = "{0:>5s}/{1:3s}  {2}".format(
                    str(service.port),
                    service.protocol,
                    service.service)
                self.service_list.insert(tk.END, text)
                print(service.banner)
                # print(service.servicefp)
                if "upnp" in service.service.lower():
                    self.general_fix_text += "upnp service running! - "
                    self.general_fix_text += "consider closing this service \n"
                if "msrpc" in service.service.lower():
                    self.general_fix_text += "Microsoft RPC service running - "
                    self.general_fix_text += "Check your router firewall to "
                    self.general_fix_text += "make sure this is not exposed "
                    self.general_fix_text += "outside of your network"
                if service.port == 5357:
                    self.general_fix_text += "Port 5357 is open, it is normally used by Microsoft Network Discovery: \n Make sure it is Filtered on public networks, and the Firewall only accepts connections from the local network"  # noqa
        if len(self.device.get_open_ports()) > 0:
            self.general_fix_text += "{0} ports are open. - ".format(
                len(self.device.get_open_ports()))
            self.general_fix_text += "consider closing or filtering them if possible \n"  # noqa
        self.general_fix_text += "Most vulnerabilities are fixed via updates - ensure your device is up to date \n"  # noqa
        self.general_fix_text += "Check your router firewall to make sure local services are not exposed to the internet"  # noqa
        self.general_label['text'] = self.general_fix_text
        # list of vulnerability frames
        self.vulnerability_list = []
        # label for number of results
        self.results_label = tk.Label(
            self.details_frame)
        # frame for found vulnerabilities
        self.scroll_results_frame = tk.Frame(self.details_frame)
        self.results_frame = tk.Frame(self.scroll_results_frame)
        self.results_frame.grid(row=0, column=0)
        # frame for the scroll buttons
        self.scroll_frame = tk.Frame(self.scroll_results_frame)
        self.scroll_frame.grid(row=0, column=1, sticky='NSE')
        # scroll up
        self.scroll_up_button = tk.Button(
            self.scroll_frame,
            text="^",
            command=lambda: self.scroll_vulnerabilities(1))
        self.scroll_up_button.pack(side=tk.TOP)
        # scroll down
        self.scroll_down_button = tk.Button(
            self.scroll_frame,
            text="v",
            command=lambda: self.scroll_vulnerabilities(-1))
        self.scroll_down_button.pack(side=tk.BOTTOM)
        self.scroll_results_frame.grid(row=4, column=0)
        # display in grid
        results = vulnerability_dict[self.device.address]
        for r in results:
            print(r[0])
            link = ""
            if r[0][:3] == "CVE":
                base = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
                link = "{0}{1}".format(base, r[0])
            else:
                print(r[0])
                base = "https://www.exploit-db.com/exploits/"
                link = "{0}{1}/".format(base, r[0])
            self.vulnerability_list.append(vulnerability_frame(
                self.results_frame,
                len(self.vulnerability_list),
                r[0],
                r[2],
                link))
        for v in self.vulnerability_list:
            if v.index < 4:
                v.layout_frame.grid(row=v.index, pady=5)
        # label for number of results
        self.results_label['text'] = "Found {0} Potential Vulnerabilities".format(  # noqa
            len(self.vulnerability_list))
        self.results_label.grid(row=3, column=0)
    # end of __init__ function

    # function to scroll through vulnerabilities
    def scroll_vulnerabilities(self, amount):
        # check if we need to scroll
        canscroll = 0
        for vulnerability in self.vulnerability_list:
            if ((vulnerability.index < 0 and amount > 0)
               or (vulnerability.index > 3 and amount < 0)):
                    canscroll = 1
        # if we do then scroll
        if canscroll == 1:
            for vulnerability in self.vulnerability_list:
                vulnerability.index = vulnerability.index + amount
                if vulnerability.index < 0 or vulnerability.index > 3:
                    vulnerability.layout_frame.grid_forget()
                else:
                    vulnerability.layout_frame.grid(row=vulnerability.index,
                                                    pady=5)
    # end of scroll_devices method

# end of details_frame class


# class for frame to allow searching of CVE vulnerabilities
class search_frame:
    def __init__(self, master):
        self.master = master
        # frame to hold everything
        self.search_frame = tk.Frame(master)
        # title label
        self.title_label = tk.Label(self.search_frame,
                                    text="Search for vulnerabilites",
                                    anchor='w')
        self.title_label.grid(row=0, column=0, sticky='W')
        # search entry and button
        self.entry_frame = tk.Frame(self.search_frame)
        self.entry_frame.grid(row=1, column=0)
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(self.entry_frame,
                                     textvariable=self.search_var,
                                     width=50)
        self.search_entry.grid(row=0, column=0, sticky='W')
        self.search_button = tk.Button(self.entry_frame,
                                       text="Search",
                                       command=self.perform_search,
                                       padx=2,
                                       pady=2)
        self.search_button.grid(row=0, column=1, sticky='W')
        # list of vulnerability frames
        self.vulnerability_list = []
        # label for number of results
        self.results_label = tk.Label(
            self.search_frame)
        # frame for found vulnerabilities
        self.scroll_results_frame = tk.Frame(self.search_frame)
        self.results_frame = tk.Frame(self.scroll_results_frame)
        self.results_frame.grid(row=0, column=0)
        # frame for the scroll buttons
        self.scroll_frame = tk.Frame(self.scroll_results_frame)
        self.scroll_frame.grid(row=0, column=1, sticky='NSE')
        # scroll up
        self.scroll_up_button = tk.Button(
            self.scroll_frame,
            text="^",
            command=lambda: self.scroll_vulnerabilities(1))
        self.scroll_up_button.pack(side=tk.TOP)
        # scroll down
        self.scroll_down_button = tk.Button(
            self.scroll_frame,
            text="v",
            command=lambda: self.scroll_vulnerabilities(-1))
        self.scroll_down_button.pack(side=tk.BOTTOM)
    # end of __init__ function

    # function to perform search
    def perform_search(self):
        for v in self.vulnerability_list:
            v.layout_frame.destroy()
        self.vulnerability_list = []
        print("searching for: {0}".format(self.search_var.get()))
        results = lookup_vulnerability(self.search_var.get())
        # add each result to list
        self.scroll_results_frame.grid(row=3, column=0)
        for r in results:
            print(r[0])
            link = ""
            if r[0][:3] == "CVE":
                base = "https://cve.mitre.org/cgi-bin/cvename.cgi?name="
                link = "{0}{1}".format(base, r[0])
            else:
                print(r[0])
                base = "https://www.exploit-db.com/exploits/"
                link = "{0}{1}/".format(base, r[0])
            self.vulnerability_list.append(vulnerability_frame(
                self.results_frame,
                len(self.vulnerability_list),
                r[0],
                r[2],
                link))
        # label for number of results
        self.results_label['text'] = "Found {0} results".format(
            len(self.vulnerability_list))
        self.results_label.grid(row=2, column=0)
        # display in grid
        for v in self.vulnerability_list:
            if v.index < 4:
                v.layout_frame.grid(row=v.index, pady=5)
    # end of perform_search function

    # function to scroll through vulnerabilities
    def scroll_vulnerabilities(self, amount):
        # check if we need to scroll
        canscroll = 0
        for vulnerability in self.vulnerability_list:
            if ((vulnerability.index < 0 and amount > 0)
               or (vulnerability.index > 3 and amount < 0)):
                    canscroll = 1
        # if we do then scroll
        if canscroll == 1:
            for vulnerability in self.vulnerability_list:
                vulnerability.index = vulnerability.index + amount
                if vulnerability.index < 0 or vulnerability.index > 3:
                    vulnerability.layout_frame.grid_forget()
                else:
                    vulnerability.layout_frame.grid(row=vulnerability.index,
                                                    pady=5)
    # end of scroll_devices method
# end of search_frame class


# class for frame to show vulnerability info
class vulnerability_frame:
    def __init__(self, master, index, id, description, link):
        self.master = master
        self.index = index
        self.link = link
        self.description = description
        # frame to hold everything
        self.layout_frame = tk.Frame(master, relief='ridge', borderwidth=2)
        self.header_frame = tk.Frame(self.layout_frame)
        self.header_frame.grid(row=0, column=0)
        # label for vulnerability id
        self.id_label = tk.Label(self.header_frame,
                                 text="Vulnerability ID: {0}".format(id))
        self.id_label.grid(row=0, column=0, sticky='W')
        # vulnerability description Label
        self.desc_label = tk.Label(self.layout_frame,
                                   text="Description:",
                                   anchor='w')
        self.desc_label.grid(row=1, column=0, sticky='W')
        # vulnerability description text
        self.desc_text = tk.Text(self.layout_frame,
                                 width=100,
                                 height=3,
                                 wrap='word')
        self.desc_text.insert("end", description)
        self.desc_text.grid(row=2, columnspan=2, column=0, sticky='W')
        # link button (opens web browser)
        self.link_button = tk.Button(self.header_frame,
                                     text="View on web",
                                     command=self.open_in_browser)
        self.link_button.grid(row=0, column=1, sticky='W')
        # label for fixes
        # self.fixes_label = tk.Label(self.layout_frame,
        #                             text="Possible Fixes:",
        #                             anchor='w')
        # self.fixes_label.grid(row=1, column=2, sticky='W')
        # text box for suggested fixes
        # self.fixes_text = tk.Text(self.layout_frame,
        #                           width=100,
        #                           height=3,
        #                           wrap='word')
        # self.fixes_text.grid(row=2, columnspan=2, column=2, sticky='W')
    # end of __init__ function

    # function to view vulnerability on the web
    def open_in_browser(self):
        try:
            webbrowser.open_new_tab(self.link)
        except Exception:
            print(Exception)
    # end of open_in_browser function

    # function to suggest fix
    # def suggest_fix(self):
    #     fixes = []
    #    fixes.append("Most vulnerabilities are fixed via updates - ensure your device is up to date")
    #    if "remote" in self.description.lower():
    #        fixes.append("Consider configuring your firewall to block external access to this service")

# end of vulnerability_frame class


# class for frame to allow testing of passwords
class password_frame:
    def __init__(self, master):
        self.master = master
        # frame to hold everything
        self.password_frame = tk.Frame(master)
        # title label
        self.title_label = tk.Label(self.password_frame,
                                    text="Password Checker")
        self.title_label.grid(row=0, column=0)
        # entry, button to test
        self.username = tk.StringVar()
        self.username_entry = tk.Entry(
            self.password_frame,
            width=40,
            textvariable=self.username)
        self.username_entry.grid(row=1, column=1, sticky='W')
        self.username_label = tk.Label(
            self.password_frame,
            text="Username:")
        self.username_label.grid(row=1, column=0)
        self.password = tk.StringVar()
        self.password_label = tk.Label(self.password_frame, text="Password:")
        self.password_label.grid(row=2, column=0)
        self.password_entry = tk.Entry(
            self.password_frame,
            exportselection=0,
            width=40,
            show='*',
            textvariable=self.password)
        self.password_entry.grid(row=2, column=1, sticky='W')
        self.check_button = tk.Button(
            self.password_frame,
            text="Check Password",
            command=self.check_password)
        self.check_button.grid(row=3, column=1, padx=65, sticky='W')
        # label for password strength feedback
        self.length_label = tk.Label(self.password_frame)
        self.characters_label = tk.Label(self.password_frame)
        self.matching_label = tk.Label(self.password_frame)
        self.list_label = tk.Label(self.password_frame)
        self.strength_label = tk.Label(self.password_frame)
    # end of __init__ function

    # function to test password
    def check_password(self):
        # test if username is contained in password
        strength_rating = 0
        if self.password_entry.get() == "":
            return
        if self.username_entry.get() == self.password_entry.get():
            text = "SEVERE: Username and password are the same"
            strength_rating -= 100
        elif self.username_entry.get() == "":
            text = "No username given"
            strength_rating += 1  # can't test against username if not given
        elif self.username_entry.get() in self.password_entry.get():
            text = "WARNING: Password contains username"
            strength_rating -= 1
        else:
            text = "GOOD: Password does not contain username"
            strength_rating += 1
        self.matching_label['text'] = text
        self.matching_label.grid(row=4, column=1)
        # test password length
        length = len(self.password_entry.get())
        if length < 8:
            text = "WARNING: Password length short"
            strength_rating -= 1
        elif length < 12:
            text = "OK: Password is 8 or more characters long"
            strength_rating += 1
        else:
            text = "GOOD: Password is 12 or more characters long"
            strength_rating += 2
        self.length_label['text'] = text
        self.length_label.grid(row=5, column=1)
        # test password character types
        types = []
        all_types = [
            "Numbers",
            "Lowercase",
            "Uppercase",
            "Special characters (Punctuation etc.)"]
        if re.search("[0-9]", self.password_entry.get()):
            types.append("Numbers")
        if re.search("[a-z]", self.password_entry.get()):
            types.append("Lowercase")
        if re.search("[A-Z]", self.password_entry.get()):
            types.append("Uppercase")
        if re.search("[^a-zA-Z0-9]", self.password_entry.get()):
            types.append("Special characters (Punctuation etc.)")
        strength_rating += (len(types)-1)
        for type in types:
            if type in all_types:
                all_types.remove(type)
        if len(all_types):
            text = "Password does not contain: "
            for type in all_types:
                text += "{0}, ".format(type)
            text = text[:-2]
        else:
            text = "GOOD: Password contains mixture of uppercase, lowercase,"
            text += " numbers and special characters"
        self.characters_label['text'] = text
        self.characters_label.grid(row=6, column=1)
        # test password against wordlist
        with open("top_10_million_top_1_mil.txt", 'r',
                  encoding='utf-8') as password_file:
            password_list = [line.rstrip() for line in password_file]
            if self.password_entry.get() in password_list:
                print("Found password!")
                strength_rating -= 100
                text = "SEVERE: Password found in common passwords list"
            else:
                text = "Password not in list"
            self.list_label['text'] = text
            self.list_label.grid(row=7, column=1)
        if strength_rating < 1:
            self.strength_label['text'] = "Password Strength: Minimal"
        elif strength_rating < 4:
            self.strength_label['text'] = "Password Strength: Weak"
        elif strength_rating < 6:
            self.strength_label['text'] = "Password Strength: OK"
        else:
            self.strength_label['text'] = "Password Strength: Strong"
        self.strength_label.grid(row=8, column=1)

        # overall strength rating
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
            # print scan result (debug)
            print_scan(report)
            # add each host to the detailed results
            for host in report.hosts:
                detailed_scan_results[host.address] = host
                # lookup vulnerabilities for that device
                find_device_vulnerabilities(host)
        # add message to queue to say detailed scan is done
        self.queue.put("detailed scan finished")
    # end of run function

    def run_scan(self, IP):
        print("scanning for {0}".format(IP))
        parsed = None
        nmproc = NmapProcess(IP, options="-A -T4 p1-65535")
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


# def detect_vulnerabilities(device_name, device_os, device_ip):
#     print("Detecting vulnerabilities for: {0}".format(device_ip))
#     host = detailed_scan_results[device_ip]
#     vulnerabilities = []
#     for service in host.services:
#         vulnerabilities += lookup_vulnerability(service.service)


# function to lookup a vulnerability based on a search term
def lookup_vulnerability(search_term, additional_term=""):
    if search_term == "":
        return []
    found = []
    print("searching {0}".format(search_term + additional_term))
    with open('Mitre_CVE_database.csv', encoding='ISO 8859-1') as database:
        cve_reader = csv.reader(database)
        for data in cve_reader:
            try:
                # convert to lowercase to improve matching
                # if additional_term != "":
                if (search_term.lower() in data[2].lower() and
                        additional_term.lower() in data[2].lower()):
                        found.append(data)
                # if search_term.lower() in data[2].lower():
                #    found.append(data)
            except Exception:
                print(Exception)
    with open('exploitdb.csv', encoding='ISO 8859-1') as database:
        cve_reader = csv.reader(database)
        for data in cve_reader:
            try:
                # convert to lowercase to improve matching
                # if additional_term != "":
                if (search_term.lower() in data[2].lower() and
                        additional_term.lower() in data[2].lower()):
                        found.append(data)
                # if search_term.lower() in data[2].lower():
                #    found.append(data)
            except Exception:
                print(Exception)
    return found
# end of lookup_vulnerability function


# function to lookup vulnerabilities for device
def find_device_vulnerabilities(device, dev_os="", dev_name=""):
    # for v in vulnerability_list:
    #    v.layout_frame.destroy()
    # vulnerability_list = []
    print("vulnerability search for: {0}".format(device.address))
    results = []
    # search for each service
    for service in device.services:
        if service.state == "open" and service.banner:
            for cpe in service.cpelist:
                print(cpe.get_product())
                if cpe.get_product() and not cpe.is_operating_system():
                    results += lookup_vulnerability(
                        cpe.get_product(),
                        cpe.get_version())
    # search for vendor and operating system
    if dev_os != "" and dev_os != "unknown" and device.vendor != "":
        results += lookup_vulnerability(device.vendor, dev_os)
    # search for device name
    if dev_name != device.address and dev_name != "":
        results += lookup_vulnerability(dev_name)
    # add each result to list
    vulnerability_dict[device.address] = results
    # set vulnerability dictionary entry for this device


root = tk.Tk()
my_gui = main_GUI(root)
root.mainloop()
