#!/bin/bash
#
#  Connection wrapper and working example for remote.it P2P Connections
#  connectd is run in P2P initiator mode
#
#----------------------------
# To list services in your account:
#
# ./p2p-init.sh <-v> <-v> -l <-p protocol>
# Adding -p protocol to the command line where protocol is one of:
# ssh
# http
# vnc
# tcp
# rdp
#
# will restrict the listing to only Services which match that protocol.
# http should be used for both http and https Services.
#
#----------------------------
# for SSH:
#
# ./p2p-init.sh <-v> <-v> <user@>ssh_servicename
#
#  ssh_servicename is the name of the remote.it Service for your ssh connection
#
#  if <user@> is not added, the current username will be used for ssh login on the remote system.
#  When you exit/logout from the ssh session, the P2P connection will terminate automatically.
#
#----------------------------
# for all other protocols:
#
# ./p2p-init.sh <-v> <-v> servicename
# The P2P connection will terminate when you press the Enter key.
#
#----------------------------
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

#set -x

#### Settings #####
VERSION=1.0.11
MODIFIED="May 24, 2019"
# Notes
#
#${var#*SubStr}  # will drop begin of string upto first occur of `SubStr`
#${var##*SubStr} # will drop begin of string upto last occur of `SubStr`
#${var%SubStr*}  # will drop part of string from last occur of `SubStr` to the end
#${var%%SubStr*} # will drop part of string from first occur of `SubStr` to the end

#
# Config Dir
#
REMOTEIT_DIR="$HOME/.remoteit"
USER="$REMOTEIT_DIR/user"
ENDPOINTS="$REMOTEIT_DIR/endpoints"
AUTH="$REMOTEIT_DIR/auth"
CONNECTION_LOG="$REMOTEIT_DIR/log.$$.txt"
#
# connectd daemon name expected on the client
# This is supplied by a symlink to the architecture specific connectd daemon.
#
EXE=connectd
#
# Save Auth in homedir
#
SAVE_AUTH=1
#
# authtype controls what is asked for. 0 => password, 1 => authhash
authtype=0 
#
# use/store authhash instead of password (recommended)
# authhash is retrieved from login API if you use password to log in
# using the authhash for connectd P2P initiator mode is faster than using password
USE_AUTHHASH=1
#
# serviceType is set to "ALL" by default for listing services.
# You can add <-p protocol> to narrow the search results to only those that match protocol.
serviceType=ALL
#
apiMethod="https://"
apiVersion="/apv/v27"
apiServer="api.remot3.it"
apikey="remote.it.developertoolsHW9iHnd"
pemkey=""
startPort=33000
#
#
# Global Vars if set will not ask for these
#
USERNAME=""
PASSWD=""
AHASH=""
#
# Other Globals
#
SERVICE_ADDRESS=""
SERVICE_STATE=""
LIST_ONLY=0
VERBOSE=0
DEBUG=0
PID=0;
TIMEIT=0
FAILTIME=10
#
# API URL's
#
loginURLpw="${apiMethod}${apiServer}${apiVersion}/user/login"
loginURLhash="${apiMethod}${apiServer}${apiVersion}/user/login/authhash"
deviceListURL="${apiMethod}${apiServer}${apiVersion}/device/list/all"
##### End Settings #####

#
# Built in manpage
#
manpage()
{
#
# Put manpage text here
#
read -d '' man_text << EOF

p2p-init.sh - A connection wrapper for remote.it showing use of the client-side daemon for a P2P connection.
This demo script is suitable for managing a small list (up to 25) of devices.
It has been tested on Ubuntu and Raspbian.  At the moment it is not compatible with macOS.

------------------------------------------
This software allows you to make Peer to peer (P2P) connections to your remote.it enabled servers.

Your username and authhash will be stored in ~/.remoteit/auth.  In the event of a "102] login failure" error, delete this file and try again.

To get a list of all services associated with your account, use:

./p2p-init.sh -l -p [protocol]

where [protocol] is one of: ssh, vnc, http, tcp, or rdp
If you leave off <-p protocol> then all services registered to your account are shown.

To make an ssh P2P connection, use:

./p2p-init.sh username@service-name

username is the ssh login name of the device.  For Raspberry Pi Raspbian OS, this is usually "pi".  
Other embedded OSes often use "root".

service-name is the remote.it name you gave to this device's SSH Service.

If your Service name has spaces in it, surround "username@service name" with quotes.

To make a connection to any protocol other than ssh, use:

./p2p-init.sh service-name

If your Service name has spaces in it, surround "service-name" with quotes.

Verbose output

To get more information about the internal operation of the script, use one or two -v switches, e.g.

./p2p-init.sh -v username@device-name

./p2p-init.sh -v -v username@device-name

Clearing the cache

To clear out all cached data (port assignments, device list)

./p2p-init.sh -r

Connection times may be a little slower and you may get connection security warnings after doing this 
until all services have been connected to once.

To cleanup (reset login authorization and active port assignments)

./p2p-init.sh -c

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
        echo "Version $VERSION Build $MODIFIED" >&2
        echo "Usage: $0 [-v (verbose)] [-v (maximum verbosity)] [-l(ist services only)] [-c(leanup)] [-r(eset to default)] [-m(an page)] [-i (use PEM key for SSH login)] [-h (this message)] [-p protocol] [user@]<servicename> [passed on to ssh]" >&2
        echo "[items in brackets are optional] " >&2
        echo "You must specify the service name." >&2
        echo "In listing mode (-l), you can optionally specify the protocol to show only matching services".
        echo "protocol should be ssh, vnc, tcp, rdp, or http." >&2
        echo "-i and user@ are only used with connections to ssh Services" >&2
        exit 1 
}


######### Begin Portal Login #########

getUserAndPassword() #get remote.it user and password interactively from user
{
    if [ "$USERNAME" != "" ]; then 
        username="$USERNAME"
    else
        printf "\n\n\n"
        printf "Please enter your remote.it account username (email address): \n"
        read username
    fi

    if [ "$AHASH" != "" ]; then
        authtype=1
        ahash="$AHASH"
    else    

        if [ "$PASSWD" != "" ]; then
            password="$PASSWD"
        else
            printf "\nPlease enter your password: \n"
            read  -s password
        fi
    fi
}

######### Wait for log event ########
#
# log_event, this funcion is the P2P connection manager for the session, it monitors the P2P engine for connection and
#   Failure Status.  Once a connection has been established, this script terminates
#
log_event()
{
    ret=0

    # create subshell and parse the logfile, modified to work around mac osx old bash
    # ( echo $BASHPID; tail -f $1) | while read LINE ; do
    (echo $(sh -c 'echo $PPID'); tail -f $1) | while read LINE ; do
        if [ -z $TPID ]; then
            TPID=$LINE # the first line is used to store the previous subshell PID
        else
            if [ $VERBOSE -gt 1 ]; then
                echo "log>>$LINE"
            fi

            case "$LINE" in
                *auto\ connect\ failed*)
                    kill -3 $TPID
                    echo "Cannot create a connection to service $service_name."
                    return 4
                    ;;
                *proxy\ startup\ failed*)
                    kill -3 $TPID            
                    echo "Port $port in use already, cannot bind to port."
                    return 1
                    ;;
                *Proxy\ started.*)
                    kill -3 $TPID 
                    echo
                    if [ $VERBOSE -gt 0 ]; then
                        echo "P2P tunnel connected on port $port." 
                    fi
                    return 0
                ;;
                *usage:*)
                    kill -3 $TPID
                    echo "Error starting connectd daemon."
                    return 2
                    ;;
                *command\ not\ found*)
                    kill -3 $TPID
                    echo "connectd daemon not found in path."
                    return 3
                    ;;
                *state\ 5*)
                    printf "."
                    if [ $VERBOSE -gt 0 ]; then
                        echo
                        echo "Connected to service, starting P2P tunnel."
                    fi
                    ;;
                *connection\ to\ peer\ closed\ or\ timed\ out*)
                    echo "Connection closed or timed out."
                    exit
                    ;;
                *!!status*)
                    printf "."
                    ;; 
            esac
        fi
    done

    ret=$?
    #echo "exited"
    return $ret 
}

# userLogin
# returns 1 if logged in, token is set
# returns 0 if not logged in login error is set
userLogin () #Portal login function
{
    printf "Logging in...\n"
#    echo "loginURLpw=$loginURLpw"
#    echo "username=$username"
#    echo "password=$password"
#    echo 
    
    if [ $authtype -eq 1 ]; then
#        resp=$(curl -s -S -X GET -H "content-type:application/json" -H "apikey:${apikey}" "$loginURLhash/$username/$ahash")
        resp=$(curl -s -S -X POST -H "apikey: ${apikey}" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -d "{ \"username\" : \"$username\", \"authhash\" : \"$ahash\" }" "$loginURLhash")
    else
        resp=$(curl -s -S -X POST -H "apikey: ${apikey}" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -d "{ \"username\" : \"$username\", \"password\" : \"$password\" }" "$loginURLpw")
    fi

#    echo "resp=$resp"

    status=$(jsonval "$(echo -n "$resp")" "status")

    login404=$(echo "$resp" | grep "404 Not Found" | sed 's/"//g')

    if [ "$login404" ]; then
        # 404 error
        loginerror="[404] API not found"
        return 0
    fi

    if [ "$status" == "true" ]; then
        # good, get token
        #token=$(jsonval "$(echo -n "$resp")" "token")
        token=$(jsonval "$resp" "token")
        date +"%s" > ~/.remoteit/.remot3it_lastlogin
        # get auth hash
        ahash=$(jsonval "$resp" "service_authhash")
#        echo "Got authhash >>$ahash"
        ret=1
    else
        loginerror=$(jsonval "$(echo -n "$resp")" "reason") 
        ret=0
    fi

    return "$ret"
}
 
######### End Portal Login #########

######### Service List ########
deviceList()
{
    resp=$(curl -s -S -X GET -H "content-type:application/json" -H "apikey:$apikey" -H "token:${token}" "$deviceListURL")
    echo $resp
}


#
# cleanup files that could affect normal operation if things went wrong
#
cleanup_files()
{
    if [ $VERBOSE -gt 0 ]; then
        printf "Cleaning up remote.it runtime files.  Removing auth file and active files.\n"
    fi   
    # reset auth
    rm -f $AUTH
    # reset active files
    rm -f ${REMOTEIT_DIR}/*.active
}
#
# Delete all the stuff in ~\.remoteit to reset to default.  You may have to clean up your .ssh/known_hosts
# to get rid of ssh connection errors if your connections land on different ports
#
resetToDefault()
{
    if [ $VERBOSE -gt 0 ]; then
        printf "Resetting remote.it settings to default.\n"
    fi   
    rm -f ${REMOTEIT_DIR}/*
}


#
# Config directory creation if not exist and setup file permissions
#
create_config()
{
    umask 0077
    # create remoteit directory
    if [ ! -d "$REMOTEIT_DIR" ]; then
        mkdir "$REMOTEIT_DIR" 
    fi
    # create files if they do not exist
    if [ ! -f "$ENDPOINTS" ] ; then
        touch "$ENDPOINTS"
    fi
    # cleanup old log files
    rm -f $REMOTEIT_DIR/*.txt
}
#
# Cleanup, this cleans up the files for the connection, and kills the P2P session if necessary
#
cleanup()
{
    if [ $DEBUG -eq 0 ]; then

        if [ $VERBOSE -gt 0 ]; then
            printf "Removing connection log.\n"
        fi    

        rm $CONNECTION_LOG
    else
        if [ $VERBOSE -gt 0 ]; then
            printf "Debug Mode, connection log is in $CONNECTION_LOG.\n"
        fi
    fi

    if [ $pid > 0 ]; then
        if [ $VERBOSE -gt 0 ]; then
            printf "Kill connection pid $pid.\n"
        fi
        kill $pid
    fi
    # cleanup port active file
    if [ -f "$REMOTEIT_DIR/${port}.active" ] ; then
        if [ $VERBOSE -gt 0 ]; then
            printf "Remove active flag file $REMOTEIT_DIR/${port}.active.\n"
        fi
        rm $REMOTEIT_DIR/${port}.active
    fi
}

#
# Control C trap
#
ctrap()
{
    if [ $VERBOSE -gt 0 ]; then
        echo "ctrl-c trap"
    fi

    cleanup
    exit 0;
}

#
# Find next unused port, returns the port to use, searches the $ENDPOINT cache
#
next_port()
{
    port=$startPort
    while [  1 ]; do
        # check if used
        grep "TPORT${port}" $ENDPOINTS > /dev/null 2>&1
        
        if [ $? = 1 ]; then
            # not found use this port
            break
        fi 

        let port=port+1
    done

    echo "$port"

}
#
# check_auth_cache, one line auth file, type is set to 0 for password and 1 for authash
# 
# Returns $username $password $type on success
#
check_auth_cache()
{
    # check for auth file
    if [ -e "$AUTH" ] ; then
        # Auth file exists, lets get it
        read -r line < "$AUTH"
        # Parse
#        username=${line%%"|"*}
        username=$(echo $line | awk -F"|" '{print $1 }')
# echo "username: $username"
#        password=${line##*"|"}
        password=$(echo $line | awk -F"|" '{print $3 }')
# echo "password: $password"
#        t=${line#*"|"}
#echo "t: $t"
        authtype=$(echo $line | awk -F"|" '{print $2 }')
#        authtype=${t%%"|"*}
# echo "authtype: $authtype"
        if [ $authtype -eq 1 ]; then
            ahash=$password
        fi
        return 1
    fi
    return 0
}

#
# Check Service Cache, return 1 if found and $port set
#
checkServiceCache()
{
    port=0

    # check if device exists, if so get port
    dev_info=$(grep "|$device|" $ENDPOINTS)

    if [ $? = 0 ]; then
        #found grab port
        p=${dev_info%%"|"*}
        port=${p##*"TPORT"}
        #Get address SERVICE_ADDRESS
        SERVICE_ADDRESS=${dev_info##*"|"}
        return 1
    fi
    return 0
}

#
#parse services
#
# fills service_array on return
#
parse_device()
{
    #parse services data into lines, this old code is not MacOS mach compatible
    #lines=$(echo "$1" | sed  's/},{/}\n{/g' )
    #lines=$(echo "$in" | sed  's/},{/}\'$'\n''{/g' )
    #lines=$(echo "$1" | sed  's/},{/}|{/g' )
    #parse lines into array 
    #readarray -t service_array < <( echo "$lines" )
    # mac friendly replacement
    #service_array=( $(echo $lines | cut -d $'\n' -f1) )
    lines=$(echo "$1" | sed  's/},{/}|{/g' )
    IFS='|'
    service_array=(  $lines )
}

#
# match_device 
#   match the passed device name to the array and return the index if found or 0 if not
#   if found service_state and service_address are set
#
match_device()
{
    # loop through the device array and match the device name
    for i in "${service_array[@]}"
    do
        # do whatever on $i
        #service_name=$(jsonval "$(echo -n "$i")" "devicealias") 
        service_name=$(jsonval "$i" "devicealias") 
   
        if [ "$service_name" = "$1" ]; then
            # Match echo out the UID/address
            #service_address=$(jsonval "$(echo -n "$i")" "deviceaddress")
            SERVICE_ADDRESS=$(jsonval "$i" "deviceaddress")
            SERVICE_STATE=$(jsonval "$i" "devicestate")
            #echo -n "$SERVICE_ADDRESS"
            return 1
        fi
    done

    #fail
    #echo -n "Not found"
    return 0
}

#
# Service List
# takes 1 parameter, SERVICE title, e.g. SSH or HTTP
#
display_services()
{
    if [ "$2" != "" ]; then
        sType="$2"
    else
        sType="$1"
    fi
    echo
    if [ "$sType" == "ALL" ]; then
        echo "All available remote.it Services"
    else
        echo "Available $sType Services"
    fi
    echo
    printf "%-40s | %-15s |  %-10s \n" "Service Name" "Service Type" "Service State"
    echo "--------------------------------------------------------------"
    # loop through the device array and match the device name
    for i in "${service_array[@]}"
    do
        # do get the metadata to display on $i
        service_name=$(jsonval "$i" "devicealias")
        service_state=$(jsonval "$i" "devicestate")
        service_service=$(jsonval "$i" "servicetitle")
        if [ "$sType" == "ALL" ]; then
            printf "%-40s | %-15s |  %-10s \n" $service_name $service_service $service_state
        elif [ "$service_service" == "$1" ]; then
            printf "%-40s | %-15s |  %-10s \n" $service_name $sType $service_state
        fi
     done
    echo
}

connect_to_it()
{
    #
    if [ "$1" == "SSH" ]; then
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
    else
        echo "$1 P2P tunnel now open on 127.0.0.1:$port"
        echo "Press the Enter key to terminate this P2P connection."
        read anykey
    fi

}
#===================================================================

#produces a unix timestamp to the output                                                                                           
utime()                                                                                                                            
{                                                                                                                                  
    echo $(date +%s)                                                                                                               
} 
#
# Produce a sortable timestamp that is year/month/day/timeofday
#
timestamp()
{
    echo $(date +%Y%m%d%H%M%S)
}


#
# Simple Long Random
#
srand()
{
    echo "$RANDOM$RANDOM" 
}

#
# dev_random() - produces a crypto secure random number string ($1 digits) to the output (supports upto 50 digits for now)
#
# ret=dev_random(10)
#
dev_random()                                                                                                                        
{                                                                                                                                  
    local count=$1                                                                                                                 
    if [ "$count" -lt 1 ] || [ "$count" -ge 50 ]; then                           
        count=50;                                                                  
    fi                                                                             
    ret=$(cat /dev/urandom | tr -cd '0-9' | dd bs=$count count= 2>/dev/null)
    echo -n "$ret"                                 
} 

#                                                                                                                                  
# JSON parse (very simplistic):  get value frome key $2 in buffer $1,  values or keys must not have the characters {}[", 
#   and the key must not have : in it
#
#  Example:
#   value=$(jsonval "$json_buffer" "$key") 
#                                                   
jsonval()                                              
{
    temp=`echo "$1" | sed -e 's/[{}\"]//g' | sed -e 's/,/\'$'\n''/g' | grep -w $2 | cut -d"[" -f2- | cut -d":" -f2-`
    #echo ${temp##*|}         
    echo ${temp}                                                
}                                                   

#                                                                                                
# rem_spaces $1  - replace space with underscore (_)                                                  
#
rem_spaces()                                                                  
{
    echo "$@" | sed -e 's/ /_/g'                                                         
}      

#                                                                                                
# rem_spaces $1  - replace space with underscore (^)                                                  
#
spaces2pipe()                                                                  
{
    echo "$@" | sed -e 's/ /^/g'                                                         
}   

#                                                                                                
# rem_spaces $1  - replace ^ with space ( )                                                  
#
pipe2space()                                                                  
{
    echo "$@" | sed -e 's/^/ /g'                                                         
}                
                                               
#                   
# urlencode $1
#                                      
urlencode()                                                                           
{
#STR="$1"
STR="$@"          
[ "${STR}x" == "x" ] && { STR="$(cat -)"; }
                     
echo ${STR} | sed -e 's| |%20|g' \
-e 's|!|%21|g' \
-e 's|#|%23|g' \
-e 's|\$|%24|g' \
-e 's|%|%25|g' \
-e 's|&|%26|g' \
-e "s|'|%27|g" \
-e 's|(|%28|g' \
-e 's|)|%29|g' \
-e 's|*|%2A|g' \
-e 's|+|%2B|g' \
-e 's|,|%2C|g' \
-e 's|/|%2F|g' \
-e 's|:|%3A|g' \
-e 's|;|%3B|g' \
-e 's|=|%3D|g' \
-e 's|?|%3F|g' \
-e 's|@|%40|g' \
-e 's|\[|%5B|g' \
-e 's|]|%5D|g'

}    

###############################
# Main program starts here    #
###############################
#
# Create the config directory if not there
#
create_config

################################################
# parse the flag options (and their arguments) #
################################################
while getopts i:p:lvhmcr OPT; do
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
        ;;
      p)
        # convert input protocol string to upper case
        serviceType=${OPTARG^^}
        if [ "$serviceType" == "SSH" ]; then
            continue
        elif [ "$serviceType" == "HTTP" ]; then
            continue
        elif [ "$serviceType" == "VNC" ]; then
            continue
        elif [ "$serviceType" == "TCP" ]; then
            continue
        elif [ "$serviceType" == "RDP" ]; then
            continue
        else
            usage
            exit 0
        fi
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


if [ $VERBOSE -gt 0 ]; then
    echo "remote.it p2p-init.sh Version $VERSION $MODIFIED"
fi

# get rid of the just-finished flag arguments
shift $(($OPTIND-1))

# make sure we have something to connect to
if [ $# -eq 0 -a "$LIST_ONLY" -ne 1 ]; then
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
                echo "${username}|1|${ahash}" > $AUTH 
            else
                echo "${username}|0|${[password}" > $AUTH 
            fi
        fi      
    fi

    # get device list
    dl_data=$(deviceList)

    # parse device list
    parse_device "$dl_data"

    if [ "$LIST_ONLY" -eq 1 ]; then
        # just display list only
        # special case, https services have the title "Secure Web"
        if [ "$serviceType" == "HTTP" ]; then
            display_services "HTTP"
            display_services "Secure Web" "HTTPS"
        elif [ "$serviceType" == "RDP" ]; then
            display_services "RDP Plus" "RDP"
        elif [ "$serviceType" == "TCP" ]; then
            display_services "Generic TCP" "TCP"
        else
            display_services "${serviceType}"
        fi
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
    if [ $VERBOSE -gt 0 ]; then
        printf "Port ${port} is already active, connecting to existing tunnel.\n"
    fi
    # make serviceType upper case
    connect_to_it "${serviceType^^}"
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
    connect_to_it "$serviceType"

    echo "Done"
    
    cleanup
fi

exit 0
