SSH/WEB(http and https)/VNC examples on how to use the remote.it connectd daemon on your Linux or macOS client to create a peer to peer connection
to a remote.it Service.

You'll need to install the correct daemon on your client computer and make sure a symlink called "connectd" located in the system PATH points to this daemon.

Copy and paste the following 3 lines to your console to install the correct daemon and create the appropriate symlink.

curl -LkO https://raw.githubusercontent.com/remoteit/installer/master/scripts/auto-install.sh
chmod +x ./auto-install.sh
sudo ./auto-install.sh

If the correct daemon is not installed by auto-install.sh, you may find our connectd daemons here: 

https://github.com/remoteit/connectd

A file called "endpoints" is created in ~/.remote.it which holds the name 
and port associated with a given UID.  This makes subsequent access quicker.

A file called "auth" is created in ~/.remote.it to cache your login credentials.

Set the variable SAVE_AUTH to 0 to prevent caching login credentials.
