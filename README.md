# NessusCLI

**NessusCLI** is a Python script to handle Nessus scans from the command line (no APIs required).

**Usage:**
```
usage: nessuscli.py [-h] --host HOST [--port PORT] --username USERNAME
                    --password PASSWORD [--verify-https] [-l] [-s FOLDER]

optional arguments:
  -h, --help            show this help message and exit
  --host HOST           The host (IP or hostname) where Nessus is running on
  --port PORT           The port Nessus is listening on (default: 8834)
  --username USERNAME   Username
  --password PASSWORD   Password
  --verify-https        Verify SSL certificate (default: false)
  -l, --list-folders    List all the folders
  -s FOLDER, --get-scans FOLDER
                        List the scans contained in folder FOLDER
```

**Preview:**

<a href="https://imgflip.com/gif/nessuscli"><img src="https://i.imgflip.com/nessuscli.gif" title="NessusCLI"/></a>
