Required:
Python 3.6 or newer
(optional for upload: the requests package - pip install requests)

========

Important: run without VPN so the path matches a normal user.

Get a one-time upload token from Na Svyazi Helpdesk
(nasvyazi.org / your usual support channel).

========

Windows:
click on run.bat

or open terminal, cd to this folder, and run this command:
python3 run.py

========

Linux/macOS:
click on run.sh

or open terminal, cd to this folder, and run this command:
python3 run.py

========

What happens when you run

1. The script reminds you to run without VPN.
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

Re-send an existing CSV (no re-scan)

If upload failed after a finished scan, or you ran local-only first:

python3 app/send_results.py results/check_results_YYYYMMDD_HHMMSS.csv

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
