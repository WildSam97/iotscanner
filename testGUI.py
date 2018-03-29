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


class device_frame:
    def __init__(self, master):
        self.master = master


root = tk.Tk()
my_gui = main_GUI(root)
root.mainloop()
