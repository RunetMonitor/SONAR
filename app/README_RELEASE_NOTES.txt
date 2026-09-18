SONAR - release notes

========

1.3.6

Each domain now records the volunteer resolver's DNS rcode (ok, nxdomain,
noanswer, servfail, refused, timeout) in dns_rcode / dns_rcode_ipv6. The
OS lookup still decides whether HTTP runs; this extra UDP query keeps the
real DNS answer that used to show up only as "[Errno 8] nodename...".

The extra DNS probe (Google, Cloudflare, NSDI, Russian ISPs, …) now asks
AAAA as well as A. New CSV columns dns_probe_*_ipv6; the original
dns_probe_* columns stay IPv4 so older files still join. The 300s probe
budget is unchanged, so a slow path may finish AAAA only in part
(dns_probe_meta partial=1). Older volunteer CSVs without these columns
still upload.

If a newer script is available, the run stops after the uppercase notice
and asks before continuing (y to keep this old version, Enter or n to
stop).

========

1.3.5

Each scan writes an anonymous sonar_id (random string) into the CSV (and upload). A local
.sonar file in the script folder remembers the id for this machine on the
same public IP. Changing network/IP gets a new id. Do not send .sonar to
Helpdesk. Older volunteer scripts without this column still upload.

========

1.3.4

Each site is now checked over IPv4 and IPv6 separately. Original CSV
columns stay IPv4 so older volunteer files still join; IPv6 is extra
*_ipv6 columns. HTTPS is pinned to one address family (works on
Python 3.14). IPv4-mapped ::ffff: addresses are not treated as IPv6.
AAAA is read from DNS (and getaddrinfo AI_ALL) so macOS without a
global IPv6 route still records real IPv6 addresses.

========
1.3.3

Send could crash after a finished scan if Python was older than 3.11.
The check itself was fine, CSV already on disk. Most volunteers did not
see this (newer Python).

Fixed in this version. README now says Python 3.7 or newer; the script
and run.sh / run.bat check that at start.

========

1.3.2

Upload no longer needs the pip library requests. Standard library only.
Sending required the extra pip library requests; we
rewrote it so that library is not needed.
