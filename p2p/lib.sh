#!/bin/bash
#
# remote.it Shell Script Lib - Just a simple library of handy shell script functions
#
# mike@remote.it
#
#
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
#
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
# use/store authhash instead of password (recommended)
#
USE_AUTHHASH=1
authtype=0 
#
#
apiMethod="https://"
apiVersion="/apv/v27"
apiServer="api.remot3.it"
developerkey=""
pemkey=""
startPort=33000
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
logoutURL="${apiMethod}${apiServer}${apiVersion}/user/logout"
deviceListURL="${apiMethod}${apiServer}${apiVersion}/device/list/all"
##### End Settings #####

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
    if [ "$DEVELOPERKEY" != "" ]; then
        developerkey="$DEVELOPERKEY"
    else
       printf "\nPlease enter your Developer API key: \n"
       read developerkey
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
                    echo "P2P tunnel connected on port $port." 
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
#    echo "developerkey=$developerkey"
#    echo 
    
    if [ $authtype -eq 1 ]; then
        resp=$(curl -s -S -X GET -H "content-type:application/json" -H "developerkey:${developerkey}" "$loginURLhash/$username/$ahash")
    else
        resp=$(curl -s -S -X POST -H "developerkey: ${developerkey}" -H "Content-Type: application/json" -H "Cache-Control: no-cache" -d "{ \"username\" : \"$username\", \"password\" : \"$password\" }" "$loginURLpw")
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
        # get a token
        ahash=$(jsonval "$resp" "service_authhash")
        #echo "Got authhash >>$ahash"
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
    resp=$(curl -s -S -X GET -H "content-type:application/json" -H "developerkey:$developerkey" -H "token:${token}" "$deviceListURL")
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
        developerkey=$(echo $line | awk -F"|" '{print $4 }')
# echo "developerkey: $developerkey"
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

    # New optimized code that works with MacOS
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
        serviceType="$2"
    else
        serviceType="$1"
    fi
    echo
    echo "Available $serviceType Services"
    echo
    printf "%-30s | %-15s |  %-10s \n" "Service Name" "Service Type" "Service State"
    echo "--------------------------------------------------------------"
    # loop through the device array and match the device name
    for i in "${service_array[@]}"
    do
        # do whatever on $i
        service_name=$(jsonval "$i" "devicealias")
        service_state=$(jsonval "$i" "devicestate")
        service_service=$(jsonval "$i" "servicetitle")
        if [ "$service_service" == "$1" ]; then
            printf "%-30s | %-15s |  %-10s \n" $service_name $serviceType $service_state
        fi
        #echo "$service_name : $service_service : $service_state"
    done
    echo
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

# XML parse,: get the value from key $2 in buffer $1, this is simple no nesting allowed
#
xmlval()
{
   temp=`echo $1 | awk '!/<.*>/' RS="<"$2">|</"$2">"`
   echo ${temp##*|}
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

jsonvalx()
{
    temp=`echo $1 | sed -e 's/[{}"]//g' -e "s/,/\\$liblf/g" | grep -w $2 | cut -d":" -f2-`
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





