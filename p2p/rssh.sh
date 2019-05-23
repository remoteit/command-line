#!/bin/bash
#
#  SSH wrapper and working example for remote.it P2P Connections
#  connectd is run in P2P initiator mode
#
#  rssh <-v> <-v> <user@>ssh_servicename
#
#  ssh_servicename is the name of the remote.it Service for your ssh connection
#
#  if <user@> is not added, the current username will be used for login on the remote system.
#
#  <optional>  -v = verbose -v -v =maximum verbosity
#
#  will store info in ~/.remoteit/
#
#  License See : https://github.com/remote.it/ssh_client
#
#  remot3.it, Inc. : https://remote.it
#
#  Author : https://github.com/lowerpower
#

# include shell script lib.sh, must be in path or specify path here
source lib.sh

#set -x

#### Settings #####
VERSION=1.0.10
MODIFIED="May 23, 2019"

#
# Built in manpage
#
manpage()
{
#
# Put manpage text here
#
read -d '' man_text << EOF

RSSH - A ssh connection wrapper for remote.it showing use of the client-side daemon for a P2P connection.
------------------------------------------
This software allows you to make ssh connections to your remote.it enabled ssh servers.

Your username and password will be stored in ~/.remoteit/auth.  In the event of a "102] login failure" error, delete this file and try again.

To get a list of all services associated with your account, use:

./rssh.sh -l

To make an ssh connection to any given device, use:

./rssh.sh username@device-name

username is the ssh login name of the device.  For Raspberry Pi Raspbian OS, this is usually "pi".  Other embedded OSes often use "root".

devicename is the remote.it name you gave to this device's SSH connection.

If your device name has spaces in it, surround "username@device name" with quotes.

Verbose output

To get more information about the internal operation of the script, use one or two -v switches, e.g.

./rssh.sh -v username@device-name

./rssh.sh -v -v username@device-name

Clearing the cache

To clear out all cached data (port assignments, device list)

./rssh.sh -r

Connection times may be a little slower and you may get connection security warnings after doing this 
until all services have been connected to once.

To cleanup (reset login authorization and active port assignments)

./rssh.sh -c

After running this, you will need to log in again.

How the script works

The script starts by logging into the remote.it server to obtain a login token.  All API calls are 
documented here:

https://docs.remote.it/api-reference/overview

The user token is sent to the Service List API call in order to retrieve the full device list 
associated with this account.

From there we parse the JSON output of the device list and find the entry corresponding to the device 
name you gave.  We find the UID (JSON ["deviceaddress"]) for this entry and use this in conjunction 
with the remote.it daemon (connectd) in client mode to initiate a peer to peer connection.

/usr/bin/connectd -c <base64 of username> <base64 of password> <UID> T<portnum> <Encryption mode> <localhost address> <maxoutstanding>

-c = client mode
<base64 of username> = remote.it user name, base64 encoded
<base64 of password> = remote.it password, base64 encoded
<UID> = remote.it UID (deviceaddress metadata) for this remote.it Service
<portnum> = port to use on localhost address
<Encryption mode> = 1 or 2
<localhost address> = 127.0.0.1
<maxoutstanding> = 12

Example:
/usr/bin/connectd -c ZmF1bHReaX5lMTk9OUB5YWhvby5jb20= d5VhdmVkFjAxWg== 80:00:00:0F:96:00:01:D3 T33000 1 127.0.0.1 12

Now you have a listener at 127.0.0.1:33000 that allows a connection to your remote device's VNC service.

The command line ssh client is launched and you are greeted with a request for your SSH password.  
Until the port assignment values are cached, you may see SSH security warnings.

EOF
#
printf "\n%s\n\n\n" "$man_text"
}

#
# Print Usage
#
usage()
{
        echo "Usage: $0 [-v (verbose)] [-v (maximum verbosity)] [-l(ist services only)] [-c(leanup)] [-r(eset to default)] [-m(an page)] [-i (use PEM key for SSH login)] [-h (this message)] [user@]<devicename> [passed on to ssh]" >&2
        echo "     [optional] must specify device name." >&2
        echo "Version $VERSION Build $MODIFIED" >&2
        exit 1 
}


###############################
# Main program starts here    #
###############################
#
# Create the config directory if not there
#
echo "remote.it rssh.sh Version $VERSION $MODIFIED"
create_config

################################################
# parse the flag options (and their arguments) #
################################################
while getopts i:lvhmcr OPT; do
    case "$OPT" in
      c)
        cleanup_files
        exit 0
        ;;
      r)
        resetToDefault
        exit 0
        ;;
      i)
        pemkey=${OPTARG}
#        echo "pemkey=$pemkey"
        ;;
      m)
        manpage
        exit 0
        ;;
      l)
        LIST_ONLY=1 ;;
      v)
        VERBOSE=$((VERBOSE+1)) ;;
      h | [?])
        # got invalid option
echo "invalid"
        usage
        ;;
    esac
done

# get rid of the just-finished flag arguments
shift $(($OPTIND-1))

# make sure we have something to connect to
if [ $# -eq 0 -a "$LIST_ONLY" -ne 1 ]; then
echo "boop"
    usage
fi

in=$1

# Parse off user
if [[ $1 == *"@"* ]]; then
    #user is specified, parse off host
    user=${1%%"@"*}"@"
    device=${1##*"@"}
else
    device=$1
fi

#shift opps out
shift

#check cache to see if we have auth 
check_auth_cache
retval=$?
if [ "$retval" != 0 ]; then
    # Lets Login
    if [ $VERBOSE -gt 0 ]; then
        echo "Use stored remote.it credentials for user $username"
    fi
else
    getUserAndPassword
fi

#check device cache to see if we have device in cache
checkServiceCache
if [ $? = 1 ] && [ "$LIST_ONLY" -eq 0 ]; then
    # device found in cache, 
    if [ $VERBOSE -gt 0 ]; then
        printf "Found ${device} in cache with UID of ${SERVICE_ADDRESS} and port ${port}.  Trying fast connect, assuming credentials are valid and device is active.\n"
        #force device state as active, this may cause problems if not active
    fi
    SERVICE_STATE="active"
else

    # Login the User (future check if already logged in with token or user exists in saved form)
    userLogin
    
    # check return value and exit if error
    retval=$?
    if [ "$retval" == 0 ]
    then
        echo $loginerror
        exit 255
    fi 

    if [ $VERBOSE -gt 0 ]; then
        echo "Logged in - get device list"
    fi

    #save auth
    if [ $SAVE_AUTH -gt 0 ]; then
        if [ ! -e "$AUTH" ] ; then
            if [ $VERBOSE -gt 0 ]; then
                echo "Saving remote.it credentials for $username"
            fi
            # Save either pw or hash depending on settings
            if [ $USE_AUTHHASH -eq 1 ]; then
                echo "${username}|1|${ahash}|${developerkey}" > $AUTH 
            else
                echo "${username}|0|${[password}|${developerkey}" > $AUTH 
            fi
        fi      
    fi

    # get device list
    dl_data=$(deviceList)

    # parse device list
    parse_device "$dl_data"

    if [ "$LIST_ONLY" -eq 1 ]; then
        # just display list only
        display_services "SSH"
        exit 0
    fi

    # Match Service passed to device list
    #address=$(match_device $device)
    match_device $device 

    retval=$?
    if [ "$retval" == 0 ]
    then
        echo "Service $device not found"
        exit 255
    fi

    # check if device exists, if so get port
    dev_info=$(grep "|$device|" $ENDPOINTS)

    if [ $? = 0 ]; then
        #found grab port
        p=${dev_info%%"|"*}
        port=${p##*"TPORT"}
    else
        # else get next port
        port=$(next_port)
        #append to file
        echo "TPORT${port}|${device}|${SERVICE_ADDRESS}" >> $ENDPOINTS
    fi
fi

#if [ $VERBOSE -gt 0 ]; then
#    echo "Service-- $device address is $address"
#fi

base_username=$(echo -n "$username" | base64)

if [ $VERBOSE -gt 0 ]; then
    echo "Service $device address is $SERVICE_ADDRESS"
    echo "Service is $SERVICE_STATE"
    echo "base64 username is $base_username"
    echo "Connection will be to 127.0.0.1:$port"
    if [  -e "$REMOTEIT_DIR/${port}.active" ]; then
        echo "A connection is already active, we will reuse the existing connection on port ${port}.";
    fi
fi

#
# If device is not active we should warn user and not attach
#
if [ "$SERVICE_STATE" != "active" ]; then
    echo "Service is not active on the remote.it Network, aborting connection attempt."
    exit 1
fi


#
# now check if port is already active, we do this by checking port running file
#
if [  -e $REMOTEIT_DIR/$port.active ]; then
    # port is active, lets just connect to it
    echo "102"
    if [ $VERBOSE -gt 0 ]; then
        printf "Port ${port} is already active, connecting to existing tunnel.\n"
        echo "Running command>> ssh ${user}127.0.0.1 -p$port"
    fi
    ssh "${user}127.0.0.1" -p$port
    #
    echo "done"

else
    #
    # need to setup a full connection
    #
    touch "$CONNECTION_LOG"    
    rm $CONNECTION_LOG
    umask 0077

    # catch ctrl C now so we can cleanup
    trap ctrap SIGINT

    if [ $VERBOSE -gt 0 ]; then
        echo "Using connection log : $CONNECTION_LOG"
    fi


    #
    # We can use a password or an Auth Hash (auth hash is a salted hashed value )
    # Auth Hash not yet tested
    #
    if [ $authtype -eq 1 ]; then
        # make the connection
        #$EXE -p "$base_username" "$ahash" "$address" "T$port" 2 127.0.0.1 0.0.0.0 15 0 0 > $CONNECTION_LOG &
        if [ $VERBOSE -gt 1 ]; then
            echo "Issuing command: $EXE -p $base_username $ahash $SERVICE_ADDRESS T$port 2 127.0.0.1 0.0.0.0 15 0 0 > $CONNECTION_LOG &"
        fi
        $EXE -s -p $base_username $ahash $SERVICE_ADDRESS T$port 2 127.0.0.1 0.0.0.0 15 0 0 > $CONNECTION_LOG 2>&1 &
        pid=$!
    else
        base_password=$(echo -n "$password" | base64)
        #
        # -c base64(yoicsid) base64(password) UID_to_connect TPort_to_bind encryption bind_to_address maxoutstanding
        #
        if [ $VERBOSE -gt 1 ]; then
            echo "Issuing command: $EXE -c $base_username $base_password $SERVICE_ADDRESS T$port 2 127.0.0.1 15 > $CONNECTION_LOG &"
        fi   
        $EXE -s -c $base_username $base_password $SERVICE_ADDRESS T$port 2 127.0.0.1 15 > $CONNECTION_LOG 2>&1 &
        pid=$!
    fi

    if [ $VERBOSE -gt 1 ]; then
        echo "Running pid $pid"
    fi


    # Wait for connectd to startup and connect
    log_event $CONNECTION_LOG

    retval=$?
    if [ "$retval" != 0 ]
    then        
        echo "Error in starting connectd daemon or connecting to $device ($retval)"
        cleanup
        exit 255
    fi
    #
    # Touch port active file
    #
    touch "$REMOTEIT_DIR/${port}.active"

    #
    #
    #
    printf "Starting SSH connection...\n"
    if [ "$pemkey" == "" ]; then
        if [ $VERBOSE -gt 0 ]; then
            echo "Running command>> ssh ${user}127.0.0.1 -p$port"
        fi
        ssh "${user}127.0.0.1" -p$port
    else
        if [ $VERBOSE -gt 0 ]; then
            echo "Running command>> ssh -i "$pemkey" ${user}127.0.0.1 -p$port"
        fi
        ssh -i "$pemkey" "${user}127.0.0.1" -p$port
    fi


    echo "Done"

    cleanup
fi

exit 0
