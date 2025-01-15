Phishing Link Scanner
A Python-based tool to analyze URLs for phishing characteristics using heuristic analysis and domain reputation checks. This tool features both a command-line interface (CLI) and a user-friendly graphical user interface (GUI) built with tkinter.

Features
Heuristic Analysis:

Detects suspicious traits such as:
IP-based URLs.
Long or excessively complex URLs.
Suspicious top-level domains (TLDs).
Use of the @ symbol in URLs.
Excessive subdomains.
Domain Reputation Check:

Performs a Whois lookup to check domain registration details and detect suspicious activity.
Identifies domains with no proper registration, private registration, or suspicious registrars.
Graphical User Interface (GUI):

Easy-to-use interface with URL input and scrollable results display.
Supports real-time analysis and output.
Requirements
Python Version:
Python 3.7 or higher
Dependencies:
Install the required libraries:

bash
Copy code
pip install python-whois
How to Run
1. Clone the Repository:
bash
Copy code
git clone https://github.com/yourusername/phishing-link-scanner.git
cd phishing-link-scanner
2. Install Dependencies:
bash
Copy code
pip install python-whois
3. Run the Application:
To run the GUI:

bash
Copy code
python TASK 1 phishing_scanner.py
Usage
Enter the URL you want to scan in the input field.
Click the "Scan URL" button.
The results will display in the scrollable text box, including:
Heuristic analysis results.
Domain reputation check results.

Acknowledgments
Whois Python Library
Tkinter GUI Documentation
