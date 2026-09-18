SONAR - release notes

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
