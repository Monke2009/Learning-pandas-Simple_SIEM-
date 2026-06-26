import pandas as pd

class ShitSIEM:
    def __init__(self):
        self. Firewall_Log = ["2026-08-01 12:00:01 ALLOW 192.168.1.5 8.8.8.8 TCP 443",
                             "2026-08-01 12:00:15 DENY 192.168.1.10 45.23.11.7 TCP 22",
                             "2026-08-01 12:01:03 DENY 192.168.1.10 45.23.11.7 TCP 22",
                             "2026-08-01 12:01:12 DENY 192.168.1.10 45.23.11.7 TCP 22 "]
        
        self.Events  = {}
        self.deniedIPs = {}

        # Storing logs
        for line in self.Firewall_Log:
            parts = line.split()
            event_key = f"Event_NO.{len(self.Events)+1}"
            self.Events[event_key] = parts

            # If IP is denied, throw it into denied IP database
            if parts[2] == "DENY":
                ip = parts[3]
                if ip in self.deniedIPs:
                    self.deniedIPs[ip] += 1
                else:
                    self.deniedIPs[ip] = 1
        
    def Analyze_logs(self):
        Display_Events = pd.DataFrame(self.Events).T
        Display_Events.columns = ['Date', 'Time', 'Action', 'Src_IP', 'Dst_IP', 'Protocol', 'Port']
        Display_Denied = pd.DataFrame(list(self.deniedIPs.items()), columns=['IP', 'Deny_Count'])

        print(Display_Events,'\n')
        print(Display_Denied,'\n')


        for ip in self.deniedIPs: # See if denied attempts exceeds 3
            if self.deniedIPs[ip] > 2: print(f"ALERT: High number of denied connection; IP: {ip}")

        for event_key, event_parts in self.Events.items(): # See if SSH activity is detected (aka port 22)
            ip = event_parts[3]
            if event_parts[6] == "22":  print(f"ALERT: SSH Activity detected; IP: {ip}")

            

ShtSIEM = ShitSIEM()
ShtSIEM.Analyze_logs()
