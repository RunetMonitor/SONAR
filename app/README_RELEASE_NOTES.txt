SONAR - release notes

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
