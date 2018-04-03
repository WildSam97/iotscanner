import tkinter as tk
from tkinter.font import Font
from tkinter import ttk as ttk


class main_GUI:
    def __init__(self, master):
        self.master = master
        master.title("IoT device Scanner")
        # frame for title, scan button etc.
        self.top_frame = tk.Frame(root)
        self.top_frame.pack(side=tk.TOP)
        # title label
        title_font = Font(family="Helvetica", size=36, weight="bold")
        self.title_label = tk.Label(self.top_frame,
                                    text="IoT Scanner",
                                    font=title_font)
        self.title_label.pack(side=tk.TOP)
        # last scan date label & variable
        self.last_scan_var = tk.StringVar()
        self.last_scan_var.set("Last scan date: Never")
        self.last_scan_label = tk.Label(self.top_frame,
                                        textvariable=self.last_scan_var)
        self.last_scan_label.pack(side=tk.LEFT)
        # button to run a new scan
        self.scan_button = tk.Button(self.top_frame,
                                     text="Run Scan")
        self.scan_button.pack(side=tk.RIGHT)
        # spacer Frame
        self.status_spacer = tk.Frame(root, height=20)
        self.status_spacer.pack(side=tk.TOP)
        # frame for scan progress stuff
        self.progress_frame = tk.Frame(root)
        self.progress_frame.pack(side=tk.TOP)
        # progress bar for scan
        self.scan_progress = ttk.Progressbar(self.progress_frame,
                                             length=200)
        self.scan_progress.pack(side=tk.LEFT)
        # status label for scan
        self.status_var = tk.StringVar()
        self.status_var.set("Scan not currently running")
        self.status_label = tk.Label(self.progress_frame,
                                     textvariable=self.status_var)
        self.status_label.pack(side=tk.RIGHT)
        # frame for device info
        self.devices_frame = tk.Frame(root)
        self.devices_frame.pack(side=tk.TOP)
        # list of devices (device frames)
        self.device_list = []
        for i in range(0, 15):
            self.device_list.append(
                device_frame(
                    self.devices_frame,
                    i,
                    i))
            # self.devices_frame.rowconfigure(i, {'minsize': 70})
    # can iterate through devices via self.device_list, and move them around:
        self.device_list[1].dev_frame.grid(row=5)
        self.device_list[5].dev_frame.grid(row=1)
    #    for device in self.device_list:
    #        row = device.dev_frame.grid_info()['row']
    #        if row - 1 < 0:
    #            device.dev_frame.grid_forget()
    #        else:
    #            row = row - 1
    #            device.dev_frame.grid(row=row)
        # frame for the scroll buttons
        self.scroll_frame = tk.Frame(root)
        self.scroll_frame.pack(side=tk.TOP)
        # scroll up
        self.scroll_up_button = tk.Button(
            self.scroll_frame,
            text="^",
            command=lambda: self.scroll_devices(1))
        self.scroll_up_button.grid(row=0, column=1)
        # scroll down
        self.scroll_down_button = tk.Button(
            self.scroll_frame,
            text="v",
            command=lambda: self.scroll_devices(-1))
        self.scroll_down_button.grid(row=9, column=1)

    # method to scroll/cycle through the devices in the device list
    def scroll_devices(self, amount):
        # check if we need to scroll
        canscroll = 0
        for device in self.device_list:
            if ((device.index < 0 and amount > 0)
               or (device.index > 9 and amount < 0)):
                    canscroll = 1
        if canscroll == 1:
            for device in self.device_list:
                device.index = device.index + amount
                if device.index < 0 or device.index > 9:
                    device.dev_frame.grid_forget()
                else:
                    device.dev_frame.grid(row=device.index)


# class for frame that contains info for specific device
class device_frame:
    def __init__(self, master, index, dev_ip):
        self.master = master
        self.index = index
        # frame to hold this device
        self.dev_frame = tk.Frame(self.master,
                                  padx=5,
                                  pady=5,
                                  borderwidth=2,
                                  relief="groove")
        if self.index >= 0 and self.index <= 9:
            self.dev_frame.grid(row=self.index)
        # frame for device info
        # self.info_frame = tk.Frame(self.dev_frame)
        # self.info_frame.grid(column=1, row=0)
        # ip address Label
        self.dev_ip_label = tk.Label(self.dev_frame,
                                     text="IP Address: {0}".format(dev_ip))
        self.dev_ip_label.grid(row=0, column=0)
        # vendor Label
        self.vendor_label = tk.Label(self.dev_frame,
                                     text="Vendor: {0}".format(dev_ip))
        self.vendor_label.grid(row=1, column=0)
        # editable device name
        # start with a label, edit button changes it to an entry, save changes
        # the label text?

        # divider?

        # frame for vulnerability info
        # self.vuln_frame = tk.Frame(self.dev_frame)
        # self.vuln_frame.grid(column=2, row=0)
        # open port Label
        self.port_label = tk.Label(self.dev_frame,
                                   text="Open ports: {0}".format(dev_ip))
        self.port_label.grid(row=0, column=1)
        # potential vulnerabilities Label
        self.vuln_label = tk.Label(
            self.dev_frame,
            text="Potential vulnerabilities: {0}".format(dev_ip))
        self.vuln_label.grid(row=1, column=1)
        # another divider?
        # show details button
        self.details_button = tk.Button(self.dev_frame, text="Show Details")
        self.details_button.grid(row=1, column=2)


# class for scrollable frame for multiple device frames?


root = tk.Tk()
my_gui = main_GUI(root)
root.mainloop()
