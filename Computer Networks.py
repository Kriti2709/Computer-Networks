import tkinter as tk 
from tkinter import ttk, messagebox
import random
import time
import threading
import re
from collections import defaultdict

# Function to validate IP address
def is_valid_ip(ip):
    if ip is None:
        return True  # Allow empty (None) IPs
    pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    if not pattern.match(ip):
        return False
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)

# Function to generate a random network packet
def generate_random_packet():
    src_ip = f"192.168.1.{random.randint(1, 255)}"
    dest_ip = f"192.168.1.{random.randint(1, 255)}"
    protocol = random.choice(["TCP", "UDP", "ICMP"])
    port = random.randint(1, 65535)
    return src_ip, dest_ip, protocol, port

# Optimized Firewall Class
class Firewall:
    def __init__(self):
        self.rules = defaultdict(list)  # Dictionary for faster rule lookup
        self.log = []

    def add_rule(self, action, src_ip=None, dest_ip=None, protocol=None, port=None):
        key = (src_ip, dest_ip, protocol, port)
        self.rules[key].append(action)

    def remove_rule(self, index):
        """Remove rule by index."""
        keys = list(self.rules.keys())  # Convert dictionary keys to list
        if index < len(keys):
            del self.rules[keys[index]]

    def match_rule(self, packet):
        key = (packet[0], packet[1], packet[2], packet[3])
        return self.rules.get(key, [None])[0]

    def process_packet(self, packet):
        action = self.match_rule(packet)
        if action is None:
            action = "BLOCK"  # Default action is now BLOCK for security

        log_entry = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {action}: Packet(src={packet[0]}, dest={packet[1]}, protocol={packet[2]}, port={packet[3]})"
        self.log.append(log_entry)
        return action

firewall = Firewall()

# Function to add a firewall rule
def add_rule():
    action = action_var.get()
    src_ip = src_ip_entry.get().strip() or None
    dest_ip = dest_ip_entry.get().strip() or None
    protocol = protocol_entry.get().strip() or None
    port = port_entry.get().strip()

    # Validate IP addresses
    if src_ip and not is_valid_ip(src_ip):
        messagebox.showerror("Error", "Invalid source IP address!")
        return
    if dest_ip and not is_valid_ip(dest_ip):
        messagebox.showerror("Error", "Invalid destination IP address!")
        return

    # Validate port number
    if port:
        if not port.isdigit() or not (1 <= int(port) <= 65535):
            messagebox.showerror("Error", "Invalid port number! Must be between 1 and 65535.")
            return
        port = int(port)

    # Validate protocol
    valid_protocols = ["TCP", "UDP", "ICMP"]
    if protocol and protocol not in valid_protocols:
        messagebox.showerror("Error", "Invalid protocol! Choose TCP, UDP, or ICMP.")
        return

    key = (src_ip, dest_ip, protocol, port)

    # Check if the packet is already blocked
    if key in firewall.rules and "BLOCK" in firewall.rules[key]:
        messagebox.showerror("Error", "This packet is already blocked! Remove the block rule before allowing it.")
        return

    firewall.add_rule(action, src_ip, dest_ip, protocol, port)
    update_rules()
    messagebox.showinfo("Success", "Rule added successfully!")

# Function to remove a selected rule
def remove_rule():
    selected_index = rule_list.curselection()
    if not selected_index:
        messagebox.showwarning("Warning", "Please select a rule to remove.")
        return
    firewall.remove_rule(selected_index[0])
    update_rules()
    messagebox.showinfo("Success", "Rule removed successfully!")

# Function to process a generated packet (Runs in a separate thread)
def generate_packet():
    packet = generate_random_packet()
    action = firewall.process_packet(packet)
    log_list.insert(tk.END, f"{action}: {packet}")

# Threaded function to avoid GUI freeze
def generate_packet_threaded():
    threading.Thread(target=generate_packet, daemon=True).start()

# Update the rules list
def update_rules():
    rule_list.delete(0, tk.END)
    for key, actions in firewall.rules.items():
        rule_list.insert(tk.END, f"{actions[0]}: {key}")

# GUI Setup
root = tk.Tk()
root.title("Firewall Simulation")
root.geometry("600x500")

# Rule Entry Frame
rule_frame = ttk.LabelFrame(root, text="Add Firewall Rule")
rule_frame.pack(pady=10, padx=10, fill="x")

ttk.Label(rule_frame, text="Action:").grid(row=0, column=0)
action_var = ttk.Combobox(rule_frame, values=["ALLOW", "BLOCK"])
action_var.grid(row=0, column=1)
action_var.current(0)

ttk.Label(rule_frame, text="Source IP:").grid(row=1, column=0)
src_ip_entry = ttk.Entry(rule_frame)
src_ip_entry.grid(row=1, column=1)

ttk.Label(rule_frame, text="Destination IP:").grid(row=2, column=0)
dest_ip_entry = ttk.Entry(rule_frame)
dest_ip_entry.grid(row=2, column=1)

ttk.Label(rule_frame, text="Protocol:").grid(row=3, column=0)
protocol_entry = ttk.Entry(rule_frame)
protocol_entry.grid(row=3, column=1)

ttk.Label(rule_frame, text="Port:").grid(row=4, column=0)
port_entry = ttk.Entry(rule_frame)
port_entry.grid(row=4, column=1)

ttk.Button(rule_frame, text="Add Rule", command=add_rule).grid(row=5, columnspan=2, pady=5)
ttk.Button(rule_frame, text="Remove Rule", command=remove_rule).grid(row=6, columnspan=2, pady=5)

# Rule List Frame
rules_frame = ttk.LabelFrame(root, text="Firewall Rules")
rules_frame.pack(pady=10, padx=10, fill="both", expand=True)
rule_list = tk.Listbox(rules_frame, height=5)
rule_list.pack(padx=10, pady=5, fill="both", expand=True)

# Log Frame
log_frame = ttk.LabelFrame(root, text="Firewall Logs")
log_frame.pack(pady=10, padx=10, fill="both", expand=True)
log_list = tk.Listbox(log_frame, height=10)
log_list.pack(padx=10, pady=5, fill="both", expand=True)

ttk.Button(root, text="Generate Packet", command=generate_packet_threaded).pack(pady=10)

root.mainloop()
