import nmap
import platform
import os
import pandas as pd
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import threading
import re  # ✅ For cleaning filenames and IP entries

def get_local_os():
    return platform.system()

def detect_os(target_ip, save_path, custom_args):
    nm = nmap.PortScanner()
    result_log = f"\n[+] Scanning {target_ip} for OS detection...\n"
    windows_hosts = []
    other_hosts = []
    raw_outputs = ""
    total_up = 0

    nmap_args = custom_args if custom_args.strip() else '-O -T4 -sT --top-ports 100'

    try:
        nm.scan(hosts=target_ip, arguments=nmap_args)
    except Exception as e:
        return f"❌ Scan failed for {target_ip}: {e}\n", False

    for host in nm.all_hosts():
        if nm[host].state() == "up":
            total_up += 1

        os_matches = nm[host].get('osmatch', [])
        if os_matches:
            best_match = os_matches[0]
            os_name = best_match['name']
            accuracy = best_match['accuracy']
            if "windows" in os_name.lower():
                windows_hosts.append((host, os_name, accuracy))
            else:
                other_hosts.append((host, os_name, accuracy))
        else:
            other_hosts.append((host, "Unknown", 0))

        raw_outputs += f"Nmap Scan Summary for {host}:\n"

        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                state = nm[host][proto][port]['state']
                name = nm[host][proto][port]['name']
                raw_outputs += f"  {proto.upper()} Port {port}: {state} ({name})\n"

        if os_matches:
            raw_outputs += "\nOS Matches:\n"
            for match in os_matches:
                raw_outputs += f"  → {match['name']} (Accuracy: {match['accuracy']}%)\n"
                for cls in match.get('osclass', []):
                    vendor = cls.get('vendor', 'Unknown')
                    osfamily = cls.get('osfamily', '')
                    osgen = cls.get('osgen', '')
                    ostype = cls.get('type', '')
                    raw_outputs += f"     - Class: {vendor} {osfamily} {osgen} ({ostype})\n"
                    cpes = cls.get('cpe', [])
                    if cpes:
                        raw_outputs += f"       CPEs: {', '.join(cpes)}\n"

        raw_outputs += "\n" + ("=" * 60) + "\n"

    os.makedirs(save_path, exist_ok=True)

    # ✅ Clean filename to avoid errors
    safe_ip = re.sub(r'[^\w.-]', '_', target_ip.strip())
    filename = os.path.join(save_path, f"{safe_ip}.txt")

    with open(filename, 'w', encoding='utf-8') as f:
        f.write(f"Local System OS: {get_local_os()}\n\n")
        f.write("--- WINDOWS HOSTS DETECTED ---\n")
        for ip, osname, acc in windows_hosts:
            f.write(f"💻 {ip} - {osname} (Accuracy: {acc}%)\n")
        f.write("\n--- OTHER OS HOSTS DETECTED ---\n")
        for ip, osname, acc in other_hosts:
            f.write(f"🧹 {ip} - {osname} (Accuracy: {acc}%)\n")
        f.write("\n--- RAW NMAP -O OUTPUTS ---\n")
        f.write(raw_outputs)
        f.write(f"\nTotal Hosts Up in {target_ip}: {total_up}\n")

    return result_log, bool(total_up)

def threaded_scan():
    file_path = filedialog.askopenfilename(
        title="Select Excel File (with IP column)",
        filetypes=[("Excel Files", "*.xlsx *.xls")]
    )
    if not file_path:
        btn.config(state=tk.NORMAL)
        return

    output_base = filedialog.askdirectory(title="Select Folder to Save Output Files")
    if not output_base:
        btn.config(state=tk.NORMAL)
        return

    output_box.delete(1.0, tk.END)

    try:
        df = pd.read_excel(file_path)
        ip_column = df['IP'].dropna().astype(str)
        ip_list = []

        # ✅ Split cells with multiple IPs (by newline or comma)
        for entry in ip_column:
            parts = re.split(r'[\n,]+', entry)
            ip_list.extend([ip.strip() for ip in parts if ip.strip()])

    except Exception as e:
        messagebox.showerror("File Error", f"❌ Failed to read Excel file: {e}")
        btn.config(state=tk.NORMAL)
        return

    custom_args = cmd_entry.get()

    for ip in ip_list:
        output_box.insert(tk.END, f"[+] Scanning IP: {ip} with args: {custom_args or 'default'}\n")
        output_box.update()
        result, _ = detect_os(ip, output_base, custom_args)
        output_box.insert(tk.END, result + "\n")
        output_box.see(tk.END)

    btn.config(state=tk.NORMAL)
    messagebox.showinfo("Scan Complete", "✅ All IPs scanned successfully!")

def start_scan():
    btn.config(state=tk.DISABLED)
    thread = threading.Thread(target=threaded_scan)
    thread.start()

# GUI setup
root = tk.Tk()
root.title("Excel-based IP OS Detection Scanner")
root.geometry("1000x750")
root.configure(bg="#f0f0f0")

frame = tk.Frame(root, bg="#f0f0f0")
frame.pack(pady=10)

btn = tk.Button(frame, text="📂 Select Excel & Start Scan", command=start_scan,
                bg="#4caf50", fg="white", font=("Arial", 12, "bold"))
btn.pack(padx=10, pady=5)

# Custom command entry
cmd_frame = tk.Frame(root, bg="#f0f0f0")
cmd_frame.pack(pady=5)
tk.Label(cmd_frame, text="Optional Custom Nmap Arguments:", font=("Arial", 10), bg="#f0f0f0").pack()
cmd_entry = tk.Entry(cmd_frame, width=100, font=("Courier New", 10))
cmd_entry.insert(0, "")  # Default is blank (uses default)
cmd_entry.pack(pady=2)

output_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=120, height=35, font=("Courier New", 10))
output_box.pack(pady=10)

root.mainloop()
