from tkinter import Tk, Label, Button, Entry, StringVar, END, W, E
import subprocess
import socket
import threading
import time
import queue

class scanGUI():

    def __init__(self, master):
        self.master = master
        master.title("IoT device Scanner")
        self.scanrunning = 0 #toggle for if a scan is currently running
        self.scanvar = StringVar() #string for scan status label
        self.scanvar.set("Scan not running")
        self.scanrunning_label_text = Label(master, textvariable=self.scanvar)
        self.scanrunning_label_text.pack()
        
        self.ipvar = StringVar() #string for local ip label
        self.ipvar.set("local IP unknown")
        self.ip_label_text = Label(master, textvariable=self.ipvar)
        self.ip_label_text.pack()
        
        self.scan_button = Button(master, text="Start scan", command = self.startscan) #button to start a scan
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
            #try: performscan(localIP)
            #finally:
            #    self.scanrunning = 0
            #    self.scanvar.set("Scan finished")
    
    def process_queue(self):
        try:
            msg = self.queue.get(0)
            self.scanrunning = 0
            self.scanvar.set("Scan finished")
        except queue.Empty:
            self.master.after(100, self.process_queue)

class ThreadedScan(threading.Thread):   
    def __init__(self, queue, localIP):
        threading.Thread.__init__(self)
        self.queue = queue
        self.localIP = localIP
    def run(self):
        #time.sleep(4)
        subprocess.run(["nmap", "-sP", "-PU161,5353", "-PA21,22,25,3389", "-PS22,3389", "-oA", "pythontestscanresult", self.localIP])
        self.queue.put("Task finished")
        #self.scanrunning = 0
        #self.scanvar.set("Scan finished")
     
   
root = Tk()
my_gui = scanGUI(root)
root.mainloop()
