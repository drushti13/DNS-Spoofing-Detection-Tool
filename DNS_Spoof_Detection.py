import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import platform
import os
import time
from collections import defaultdict
import dns.resolver
from scapy.all import sniff, DNS, DNSQR, DNSRR

# Matplotlib for graph
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False

dns_records = defaultdict(list)
TIME_THRESHOLD = 60
trusted_resolver = dns.resolver.Resolver()
trusted_resolver.nameservers = ['8.8.8.8']

class DNSMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🚨 DNS Spoofing Detection Tool")
        self.root.geometry("800x720")
        self.root.configure(bg="#f5f5f5")

        self.logs = []
        self.filter_mode = tk.StringVar(value="All Alerts")
        self.packet_counts = [0] * 60

        tk.Label(root, text="🚨 DNS Spoofing Live Alerts", font=("Arial", 16, "bold"), bg="#f5f5f5", fg="#c00").pack(pady=10)

        filter_frame = tk.Frame(root, bg="#f5f5f5")
        filter_frame.pack(pady=5)

        tk.Label(filter_frame, text="Filter: ", bg="#f5f5f5").pack(side=tk.LEFT)
        filter_dropdown = ttk.Combobox(filter_frame, textvariable=self.filter_mode, state="readonly", width=30)
        filter_dropdown["values"] = ["All Alerts", "Only Suspicious (No Answer Section)", "Only Spoofed"]
        filter_dropdown.pack(side=tk.LEFT)
        filter_dropdown.bind("<<ComboboxSelected>>", lambda e: self.refresh_log_view())

        # Export button
        export_btn = tk.Button(filter_frame, text="💾 Export Logs", command=self.export_logs, bg="#ddd", font=("Arial", 10, "bold"))
        export_btn.pack(side=tk.LEFT, padx=10)

        self.alert_box = ScrolledText(root, width=100, height=20, bg="#fff0f0", font=("Courier", 10))
        self.alert_box.pack(padx=10, pady=5)
        self.alert_box.config(state=tk.DISABLED)

        # Graph setup
        self.graph_frame = tk.Frame(root)
        self.graph_frame.pack(pady=10)
        self.figure = Figure(figsize=(7, 2.5), dpi=100)
        self.ax = self.figure.add_subplot(111)
        self.ax.set_title("📊 Live DNS Request Traffic")
        self.ax.set_xlabel("Seconds Ago")
        self.ax.set_ylabel("DNS Requests")
        self.line, = self.ax.plot(range(60), self.packet_counts, color='blue')

        self.canvas = FigureCanvasTkAgg(self.figure, master=self.graph_frame)
        self.canvas.get_tk_widget().pack()

        self.update_graph()
        threading.Thread(target=self.start_sniffing, daemon=True).start()

    def update_graph(self):
        self.packet_counts.pop(0)
        self.packet_counts.append(0)
        self.line.set_ydata(self.packet_counts)
        self.ax.relim()
        self.ax.autoscale_view()
        self.canvas.draw()
        self.root.after(1000, self.update_graph)

    def add_log(self, domain, spoofed_ip, trusted_ips, log_type):
        timestamp = time.strftime("%H:%M:%S")
        entry = {
            "timestamp": timestamp,
            "domain": domain,
            "spoofed_ip": spoofed_ip,
            "trusted": trusted_ips,
            "type": log_type
        }
        self.logs.insert(0, entry)
        self.refresh_log_view()

    def refresh_log_view(self):
        selected_filter = self.filter_mode.get()
        self.alert_box.config(state=tk.NORMAL)
        self.alert_box.delete("1.0", tk.END)

        for log in self.logs:
            if selected_filter == "Only Suspicious (No Answer Section)" and log["type"] != "suspicious":
                continue
            if selected_filter == "Only Spoofed" and log["type"] != "spoofed":
                continue

            message = f"[{log['timestamp']}]\nDomain: {log['domain']}\nSpoofed IP: {log['spoofed_ip']}\nExpected: {', '.join(log['trusted'])}\n\n"
            self.alert_box.insert("end", message)

        self.alert_box.config(state=tk.DISABLED)

    def export_logs(self):
        selected_filter = self.filter_mode.get()

        # Filter logs according to dropdown selection
        filtered_logs = []
        for log in self.logs:
            if selected_filter == "Only Suspicious (No Answer Section)" and log["type"] != "suspicious":
                continue
            if selected_filter == "Only Spoofed" and log["type"] != "spoofed":
                continue
            filtered_logs.append(log)

        if not filtered_logs:
            messagebox.showinfo("No Logs", "There are no logs matching the selected filter.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            title=f"Save {selected_filter} Logs"
        )

        if file_path:
            try:
                with open(file_path, "w") as f:
                    for log in filtered_logs:
                        line = (
                            f"[{log['timestamp']}]\n"
                            f"Domain: {log['domain']}\n"
                            f"Spoofed IP: {log['spoofed_ip']}\n"
                            f"Expected: {', '.join(log['trusted'])}\n\n"
                        )
                        f.write(line)
                messagebox.showinfo("Exported", f"Logs saved to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save logs: {e}")

    def alert_suspicious_packet(self, domain):
        self.add_log(domain, "No Answer Section", ["Expected valid response"], "suspicious")

        if PLYER_AVAILABLE:
            try:
                notification.notify(
                    title="⚠️ Suspicious DNS Packet",
                    message=f"{domain} — No answer section",
                    timeout=5
                )
            except Exception as e:
                print(f"[!] Notification failed: {e}")

        try:
            if platform.system() == "Windows":
                import winsound
                winsound.Beep(1000, 500)
            elif platform.system() == "Linux":
                os.system('play -nq -t alsa synth 0.1 sine 880')
        except Exception as e:
            print(f"[!] Sound alert failed: {e}")

    def verify_with_trusted_dns(self, domain):
        try:
            answers = trusted_resolver.resolve(domain, 'A')
            return [answer.address for answer in answers]
        except:
            return []

    def process_packet(self, packet):
        if packet.haslayer(DNS) and packet[DNS].qr == 1:
            try:
                domain = packet[DNSQR].qname.decode().strip('.')
                current_time = time.time()
                self.packet_counts[-1] += 1

                if not packet.haslayer(DNSRR):
                    print(f"[!] Suspicious DNS packet for {domain} — no answer section.")
                    self.alert_suspicious_packet(domain)
                    return

                answers = []
                for i in range(packet[DNS].ancount):
                    rr = packet[DNS].an[i]
                    if rr.type == 1:
                        answers.append(rr.rdata)

                if not answers:
                    print(f"[!] No A records found in DNS response for {domain}")
                    return

                dns_records[domain] = [
                    (ip, ts) for ip, ts in dns_records[domain]
                    if current_time - ts < TIME_THRESHOLD
                ]

                trusted_ips = self.verify_with_trusted_dns(domain)
                seen_ips = [ip for ip, _ in dns_records[domain]]

                for ip in answers:
                    if trusted_ips and str(ip) not in trusted_ips:
                        print(f"[!!!] Spoofed DNS for {domain} -> {ip}, expected {trusted_ips}")
                        self.add_log(domain, str(ip), trusted_ips, "spoofed")

                    if str(ip) not in seen_ips:
                        dns_records[domain].append((str(ip), current_time))

            except Exception as e:
                print(f"[!] Packet processing error: {e}")

    def start_sniffing(self):
        sniff(filter="udp port 53", prn=self.process_packet, store=0)

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSMonitorGUI(root)
    root.mainloop()
