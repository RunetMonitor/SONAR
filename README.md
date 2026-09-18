<p align="center">
  <img src="app/logo.jpg" alt="SONAR" width="180">
</p>

SONAR - alpha  
Na Svyazi / Runet Monitor  
License: MIT (see LICENSE)

https://github.com/RunetMonitor/SONAR

Required:  
Python 3.7 or newer  

The script checks this when it starts. If Python is too old, or a required  
standard module is missing, it stops with an error before the scan.

========

**Important:** run without VPN so the path matches a normal user.  
**Important:** use a network cable from your ISP, not a mobile hotspot.

Get a one-time upload token from Na Svyazi Helpdesk  
(nasvyazi.org / your usual support channel).

========

Windows:  
click on run.bat

or open terminal, cd to this folder, and run this command:  
`python3 run.py`

========

Linux/macOS:  
click on run.sh

or open terminal, cd to this folder, and run this command:  
`python3 run.py`

========

What happens when you run

1. The script reminds you to run without VPN, on a network cable from  
   your ISP (not a mobile hotspot).  
   If a newer version exists, it says so in uppercase at the start  
   and again at the end (GitHub/CDNs; if those are blocked, it stays quiet).
2. It asks for your one-time upload token before the scan.  
   - Paste the token from Helpdesk / support to scan and upload.  
   - Leave empty for a local-only scan (CSV saved, no upload).
3. The token is checked on your device for typos (length and checksum).  
   A bad paste aborts before scanning.
4. Upload (when a token was entered) is hop-first: the client tries known  
   hop endpoints in order, then the direct monitor URL as fallback.  
   Hop hosts may change over time; you do not configure them.
5. Auth is only that one-time token (used as the zip password and as  
   X-Web-Token). No zip password in the package. Do not edit config.py.

========

The scan also queries extra DNS servers listed in app/dns_servers.txt.  
That runs in the background during the usual check. Results go into the  
same CSV (dns_probe_* columns).

Each site is tested over IPv4 and IPv6 separately (always both; there is  
no switch). The original CSV columns stay IPv4 so older volunteer files  
still join. IPv6 is extra `*_ipv6` columns. Missing those columns means  
IPv6 was not measured. AAAA comes from DNS, not from IPv4-mapped  
`::ffff:` addresses.

========

Re-send an existing CSV (no re-scan)

If upload failed after a finished scan, or you ran local-only first:

`python3 app/send_results.py`

That uses the newest `results/check_results_*.csv` (by last-modified time).  
To send a specific file instead:

`python3 app/send_results.py results/check_results_YYYYMMDD_HHMMSS.csv`

You will be asked for a one-time token again.  
The CSV stays on disk; any temp zip is removed after the attempt.

========

Helpdesk / manual fallback

If automated upload is not possible, send the unencrypted CSV to support  
via Helpdesk / a secure channel. Do not send the encrypted zip as the  
normal manual path.

========

Operators / developers only

Optional local overrides: app/config.local.py or environment (gitignored).  
Volunteers never need this. See app/config.example.py.

========

License

Released under the MIT License. Copyright (c) 2026 Na Svyazi.  
See LICENSE.
