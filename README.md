# command-line
remote.it utilities useful in terminal based environments

\------------------------------------------
## p2p-init.sh: remote.it Peer to Peer (P2P) initiator sample script.
Demonstrates use of the remote.it connectd daemon on your Linux client to create a peer to peer 
connection to a remote.it Service.
This demo script is suitable for managing a small list (up to 25) of devices.
It has been tested on Ubuntu, Raspbian, and macOS Mojave.

\------------------------------------------
### Prerequisite:
Linux: make sure you have the connectd package installed first.  See: https://docs.remote.it/platforms/supported-platforms
Mac: as we don't have a Mac package at this time, run the following commands in a terminal window to get the Mac version of the connectd daemon onto your system and create a symbolic link for the p2p-init.sh script to use:

```shell
cd /usr/local/bin
curl -LkO https://github.com/remoteit/connectd/releases/download/v4.6/connectd.x86_64-osx
chmod +x connectd.x86_64-osx
ln -s /usr/local/bin/connectd.x86_64-osx connectd
```
------------------------------------------
Your username and authhash will be stored in ~/.remoteit/auth.  In the event of a "102] login failure" error, delete this file and try again.

### To show the built in help pages, type:
```
./p2p-init.sh -m | less
```

### To get a list of the various services associated with your account, use:

SSH:
```
./p2p-init.sh -p ssh -l 
```

http/https:
```
./p2p-init.sh -p http -l 
```

VNC:
```shell
./p2p-init.sh -p vnc -l 
```

All:
```shell
./p2p-init.sh -l 
```
### To make a connection to an SSH service then log in, use:
```
./p2p-init.sh username@service-name
```

username is the ssh login name of the device.  For Raspberry Pi Raspbian OS, this is usually "pi".  
Other embedded OSes often use "root".

service-name is the name you gave to this device's SSH remote.it Service.

If your service name has spaces in it, surround "username@device name" with quotes.

For example. supposing your SSH service is called "My SSH Service" and the login username is pi, use:
```
./p2p-init.sh "pi@My SSH Service".
```
When you log out of your ssh session, the P2P connection will be terminated.

### To make a connection to anything other than SSH, use:
```
./p2p-init.sh service-name
```
service-name is the name you gave to this device's vnc or http(s) remote.it Service.
If your service name has spaces in it, surround "service-name" with quotes, e.g.
```
./p2p-init.sh "My VNC Service".
```

The P2P connection will remain open until you press the Enter key.  This allows you to use the
localhost:port connection in your web browser or VNC application.  When you are done using the 
connection, press the Enter key to terminate the P2P connection.

### Verbose output

To get more information about the internal operation of the script, use one or two -v switches, e.g.
```
./p2p-init.sh -v username@service-name
```
Maximum debug out:
```
./p2p-init.sh -v -v service-name
```
### Clearing the cache

To clear out all cached data (port assignments, device list)
```
./p2p-init.sh -r
```
Connection times may be a little slower and you may get connection security warnings at first
until all services have been connected to once.

### To cleanup (reset login authorization and active port assignments)
```
./p2p-init.sh -c
```
After running this option, you will need to log in again.

### How the script works

The script starts by logging into the remote.it server to obtain a login token.  All API calls are
documented here:

https://docs.remote.it/api-reference/overview

The user token is sent to the Service List API call in order to retrieve the full device list
associated with this account.

From there the script parses the JSON output of the device list and find the entry corresponding to 
the device name you gave.  We find the UID (JSON ["deviceaddress"]) for this entry and use this in 
conjunction with the remote.it connectd daemon in client mode to initiate a peer to peer connection.
```
/usr/bin/connectd -p <base64 of username> <authhash> <UID> T<portnum> <Encryption mode> <localhost address> <maxoutstanding>
```
* -p = client mode, use authhash
* \<base64 of username> = remote.it user name, base64 encoded
* \<authhash> = remote.it account authhash, plain text
* \<UID> = remote.it UID (deviceaddress metadata) for this remote.it Service
* \<portnum> = port to use on localhost address
* \<Encryption mode> = 1 or 2
* \<localhost address> = 127.0.0.1
* \<maxoutstanding> = 12

Example:
```
/usr/bin/connectd -p ZmF1bHReaX5lMTk9OUB5YWhvby5jb20= aB14235CCd03459 80:00:00:0F:96:00:01:D3 T33000 1 127.0.0.1 12
```

Now you have a listener at 127.0.0.1:33000 that allows a connection to your device's remote.it Service.

### Installation
Download p2p-init.sh to your computer and make it executable using "chmod +x".

You'll need to install the correct daemon on your client computer and make sure a symlink called "connectd" 
located in the system PATH points to this daemon.

Copy and paste the following 3 lines to your console to install the correct daemon and create the appropriate symlink.

```
curl -LkO https://raw.githubusercontent.com/remoteit/installer/master/scripts/auto-install.sh
chmod +x ./auto-install.sh
sudo ./auto-install.sh
```

If the correct daemon is not installed by auto-install.sh, you may find our connectd daemons here: 

https://github.com/remoteit/connectd

### Files created
A file called "endpoints" is created in ~/.remoteit which holds the name 
and port associated with a given UID.  This makes subsequent access quicker.

A file called "auth" is created in ~/.remoteit to cache your login credentials.

### Options
Set the variable SAVE_AUTH to 0 to prevent caching login credentials.
