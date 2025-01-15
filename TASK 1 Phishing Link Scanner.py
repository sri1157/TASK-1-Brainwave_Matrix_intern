import re
import whois
from urllib.parse import urlparse
import tkinter as tk
from tkinter import messagebox, scrolledtext

# Define functions
def is_suspicious_url(url):
    """Basic heuristic analysis of a URL."""
    messages = []
    # Check for IP addresses in the URL
    if re.search(r'\b\d{1,3}(\.\d{1,3}){3}\b', url):
        messages.append("[!] URL contains an IP address. This can be suspicious.")

    # Check for long URLs
    if len(url) > 75:
        messages.append("[!] URL length is unusually long. This can be suspicious.")

    # Check for suspicious domains (e.g., unusual TLDs)
    suspicious_tlds = ['.zip', '.xyz', '.top', '.tk', '.ml', '.ga', '.cf']
    parsed_url = urlparse(url)
    if any(parsed_url.netloc.endswith(tld) for tld in suspicious_tlds):
        messages.append(f"[!] URL uses a suspicious domain ({parsed_url.netloc}).")

    # Check for '@' symbol in URL (used to obscure true domain)
    if '@' in url:
        messages.append("[!] URL contains an '@' symbol. This can be used for phishing.")

    # Check for multiple subdomains
    if parsed_url.netloc.count('.') > 3:
        messages.append("[!] URL contains too many subdomains. This can be suspicious.")

    if not messages:
        messages.append("[+] URL passed basic heuristic checks.")
    return messages

def check_domain_reputation(domain):
    """Check the domain reputation by querying Whois."""
    messages = []
    try:
        # Perform a Whois lookup on the domain to check for suspicious characteristics
        domain_info = whois.whois(domain)

        # Basic check on domain registration (new or private)
        if not domain_info.domain_name or domain_info.status == "pendingDelete":
            messages.append("[!] Domain has no proper registration details. This can be suspicious.")

        if domain_info.registrar and "phishing" in domain_info.registrar.lower():
            messages.append("[!] Domain is registered with a suspicious registrar.")
    except Exception as e:
        messages.append(f"[!] Whois lookup failed: {e}")
    
    if not messages:
        messages.append("[+] Domain reputation check passed.")
    return messages

def scan_url():
    url = url_entry.get().strip()
    if not url:
        messagebox.showerror("Input Error", "Please enter a URL to scan.")
        return

    # Clear the results box
    results_box.delete(1.0, tk.END)

    # Perform heuristic checks
    results_box.insert(tk.END, "Running heuristic analysis...\n")
    heuristic_results = is_suspicious_url(url)
    results_box.insert(tk.END, "\n".join(heuristic_results) + "\n")

    # Extract domain and perform domain reputation check
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    results_box.insert(tk.END, "\nChecking domain reputation...\n")
    domain_results = check_domain_reputation(domain)
    results_box.insert(tk.END, "\n".join(domain_results) + "\n")

    results_box.insert(tk.END, "\nScan complete.")

# GUI Setup
root = tk.Tk()
root.title("Phishing Link Scanner")
root.geometry("600x400")

# Input URL
url_label = tk.Label(root, text="Enter URL to Scan:", font=("Arial", 12))
url_label.pack(pady=10)
url_entry = tk.Entry(root, width=50, font=("Arial", 12))
url_entry.pack(pady=5)

# Scan Button
scan_button = tk.Button(root, text="Scan URL", font=("Arial", 12), command=scan_url, bg="blue", fg="white")
scan_button.pack(pady=10)

# Results Section
results_label = tk.Label(root, text="Scan Results:", font=("Arial", 12))
results_label.pack(pady=10)
results_box = scrolledtext.ScrolledText(root, width=70, height=15, font=("Arial", 10))
results_box.pack(pady=5)

# Run the app
root.mainloop()
