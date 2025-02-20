# Lab 4: The Incident Alarm

The script detects various types of scan attacks, such as NULL, FIN, Xmas, SMB, RDP, and VNC scans. The script also detects usernames and passwords sent in-the-clear over HTTP, IMAP, and FTP. This is done using TCP flags and port numbers.

## Questions:

Are the heuristics used in this assignment to determine incidents "even that good"? \
Checking for specific TCP flags (e.g. NULL, FIN, PSH, and URG flags) can detect certain types of network scans or attacks. These flags can help identify scans that probe for open ports or vulnerabilities. However, the script will generate false positives such as from legitimate traffic that contains these flags.
Detecting usernames and passwords sent in clear text (via HTTP Basic Auth, FTP, IMAP) is a strong heuristic since sending credentials in plain text is a known security risk. This helps to identify potential credential leaks or insecure authentication practices.

If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents? \
Given more time, I would add rate-based detection to track how frequently certain behaviors occur over time to detect anomalies such as multiple connection attempts in a short period which could indicate a brute force attack, or an increased number of connections to uncommon ports could better indicate scanning activity.