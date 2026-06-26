from Configs import *
import pandas as pd

class SimpleSIEM:
    def __init__(self):
        self. Firewall_Log = ["2026-08-01 12:00:01 ALLOW 192.168.1.5 8.8.8.8 TCP 443",
                             "2026-08-01 12:00:15 DENY 192.168.1.10 45.23.11.7 TCP 22",
                             "2026-08-01 12:01:03 DENY 192.168.1.10 45.23.11.7 TCP 22",
                             "2026-08-01 12:01:12 DENY 192.168.1.10 45.23.11.7 TCP 22 "]
        rows = [line.split() for line in self.Firewall_Log]

        # Get events
        self.events  = pd.DataFrame(rows, columns=["Date", "Time", "Action", "Src_IP", "Dst_IP", "Protocol", "Port"])
        self.alerts = []


    def analyze_logs(self):
        events = self.events

        self.get_multiple_denials(events)
        self.get_ssh_attemps(events)
        self.get_port_scan(events)
        self.get_SSH_brute(events)

        # Print out events and denied events
        print("ALL events: ", events, "\n")
        
        # Print out alerts
        for alert in self.alerts:
            print(f"[{alert['severity']}] "
                  f"{alert['type']} | "
                  f"{alert['ip']} | "
                  f"{alert['count']}")
        
    
    # ADD ALERT FUNC
    def add_alert(self, alert_type, ip, Count):
        if   Count >= 50: severity = "CRITICAL"
        elif Count >= 20: severity = "HIGH"
        elif Count >= 5 : severity = "MEDIUM"
        else: severity = "LOW" 

        self.alerts.append({
            "type" : alert_type,
            "severity" : severity,
            "ip" : ip,
            "count" : Count
        })


    # MULTIPLE DENIALS CHECK
    def get_multiple_denials(self, events):
        denied = events[events["Action"] == "DENY"]
        denied_cnt_alerts = denied["Src_IP"].value_counts()
        for SrcIP, Count in denied_cnt_alerts.items():
            if Count >= DENIAL_THRESHOLD:
                self.add_alert("Multiple Denials", SrcIP, Count)


    # SSH ATTEMPS CHECK
    def get_ssh_attemps(self, events):
        ssh_suspects = events[(events["Action"] == "DENY") & (events["Port"] == "22")]["Src_IP"].value_counts()
        for SrcIP, Count in ssh_suspects.items():
            if Count >= SSH_ACTIVITY_THRESHOLD:
                self.add_alert("SSH Activity", SrcIP, Count)


    # PORTS SCAN CHECK
    def get_port_scan(self, events):
        ports_per_IP = events.groupby("Src_IP")["Port"].nunique()
        for SrcIP, Count in ports_per_IP.items():
            if Count >= PORT_SCAN_THRESHOLD:
                self.add_alert("Port Scan", SrcIP, Count)


    # SSH BRUTE CHECK
    def get_SSH_brute(self, events):
        ssh_suspects = events[(events["Action"] == "DENY") & (events["Port"] == "22")]["Src_IP"].value_counts()
        for SrcIP, Count in ssh_suspects.items():
            if Count >= SSH_BRUTE_THRESHOLD:
                self.add_alert("Brute Force", SrcIP, Count)
            

ShtSIEM = SimpleSIEM()
ShtSIEM.analyze_logs()
