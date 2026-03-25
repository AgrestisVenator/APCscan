# APCscan
vibe coded python script for Windows to check SSH, Telnet, HTTPS, HTTP and FTP on Schneider network management cards for default credential pairs.

I had to check over 1600 APC UPS network management cards to mitigate the concern that they may still have the default superuser enabled.  NMCs in the environment ranged from 2007 to modern, and depending on the configuration might have any of these 5 protocols available.  For backwards compatibility, deprecated ciphers were permitted.  FTP was added to workaround certain errors in the HTTP/S interface.

Ingests 'ips.txt' and attempts up to 5 different authentication methods in parallel blocks of 20 IPs.  It stops on the first successful auth per IP, but on failure walks all protocols.

Generates a very verbose CSV file with the timestamp, IP, hostname, whether the device responded, whether port 22 is open, the status of the login attempt (success or failure), details (On what protocol is the auth success or failure?), and then breaks out the error messages by protocol.  

The success/failure criteria seems solid from my spot checking.

**WARNING**

This is intended only for use by authorized individuals for authorized activities in a given environment.

Known bad design practices include writing the default credential pair (apc/apc) to both the CSV output and a temporary file in plaintext.  If you ever use this to check other credentials, take this into consideration.  
Same consideration goes for transmission of credentials over plaintext or deprecated ciphers.  

There is some jitter baked in to avoid spiking but this script is very noisy due to multiple protocols, retries, and parallel workers.  It checks for open ports on the IPs and then attempts to auth to them.  Functionally, this is a password spray tool.  Your EDR or SIEM may take issue with it.

Web auth detection is heuristic-based and may produce false positives depending on firmware/UI variations.

