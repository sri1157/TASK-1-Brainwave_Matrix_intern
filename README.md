### **Phishing Link Scanner**  

---

## **Overview**  
This Python application is a **Phishing Link Scanner** designed to identify potentially malicious URLs. Built with the `Tkinter` library for a graphical user interface (GUI), it analyzes URLs for suspicious traits and checks domain reputation. The tool is ideal for cybersecurity enthusiasts and professionals who need to perform quick, actionable assessments.  

---

## **Key Features**  

### **Heuristic URL Analysis**  
- Detects suspicious traits, such as:  
  - URLs containing IP addresses.  
  - Long or overly complex URLs.  
  - Suspicious top-level domains (e.g., `.xyz`, `.tk`).  
  - Use of the `@` symbol (commonly used to obscure real domains).  
  - Excessive subdomains.  

### **Domain Reputation Check**  
- Performs a Whois lookup to analyze domain registration details.  
- Flags issues like:  
  - Domains with no proper registration.  
  - Use of suspicious or privacy-protected registrars.  
  - Recently created or unverified domains.  

### **User-Friendly GUI**  
- Easy-to-use interface built with `Tkinter`.  
- Real-time scanning and results display in a scrollable text box.  

### **Export Results**  
- Save analysis results and feedback to a text file for future reference.  

---

## **How It Works**  

### **Input a URL:**  
Type a URL into the input field in the GUI. The app performs a heuristic analysis and a domain reputation check.  

### **View Results:**  
The analysis results are displayed in real-time within the GUI, including warnings and safety checks.  

### **Export Results:**  
Save the detailed scan results, including feedback and domain information, to a `.txt` file with a single click.  

---

## **Code Explanation**  

### **Heuristic Analysis:**  
- Uses regular expressions to detect suspicious patterns (e.g., IP addresses, long URLs, or uncommon TLDs).  
- Identifies phishing indicators like `@` symbols or excessive subdomains.  

### **Whois Lookup:**  
- Checks domain registration details to assess the reputation of the domain.  
- Handles errors gracefully if Whois data is unavailable.  

### **GUI Implementation:**  
- Built with `Tkinter` for an intuitive, user-friendly design.  
- Includes input fields, scrollable result displays, and export buttons for convenience.  

---

## **How to Run the Code**  

### **Prerequisites:**  
Ensure you have Python 3.x installed on your system.  

### **Install Required Libraries:**  
Run the following command to install the necessary Python libraries:  
```bash  
pip install python-whois tkinter  
```  

### **Run the Application:**  
Run the script using the command:  
```bash  
python phishing_link_scanner.py  
```  

---

## **Example Use Cases**  

- **Quick URL Scans:** Analyze suspicious URLs found in emails or messages.  
- **Training Tool:** Learn about phishing techniques and domain analysis.  
- **Incident Response:** Use the scanner for initial threat identification.  


## **Customization Options**  

- Modify the heuristic analysis rules to flag additional phishing traits.  
- Integrate public APIs like PhishTank or VirusTotal for advanced URL and domain reputation checks.  
- Enhance the GUI to include more features, like batch URL scanning.  

 **Contributing**  
Contributions are welcome! If you have ideas for improving the scanner, feel free to fork the repository and submit a pull request.  

 **License**  
This project is licensed under the MIT License. See the `LICENSE` file for more details.  


