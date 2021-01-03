# SYN-Attack-Suppressor-Routine v1.2

This script stops SYN attacks.   SYN attacks use to be done from a single IP address.  They have now become more sophisticated, continuously changing the right most numbers in an IP address (ex: 001.002.003.050, 001.002.003.051, 001.002.003.052...001.002.003.100).  They have now gone even further to continuously changing the numbers in the 3rd, 2nd, and 1st positions from the right.  This script looks for multiple changes in the 3rd, 2nd, and 1st positions and blocks the 4th high order position and blocks this high order position for a selected number of minutes (ex: 123.0.0.0/8).  This script has been tested on my servers for over a year.  If you have large amounts of traffic coming into your server from all over the world, this script might block clients from the server for the block time.  See the setup instructions in the top of the script below.  

```
#!/bin/bash
# This script monitors netstat for SYN_RECV records (the responce from my server to a sync attack).
# It then retrieves the 1st left most IP numbers and adds .0.0.0/8 to it.  It is then added to a
# special chain as DROP (MY_SYN_DROP).
# Ex: iptables -A MY_SYN_DROP -s nnn.0.0.0/8 -j DROP
#
# Special chain creation instructions:
#  iptables -N MY_SYN_DROP           # create/add a chain
#  iptables -A INPUT -j MY_SYN_DROP  # open it for INPUT records
#
# Run with cron every minute: */1 * * * * /path/to/SYN_RECV_traceII.sh &> /dev/null
#


export PATH=$PATH:/sbin

filePath=${0%/*}  # current file path

# Set the time here for shutting out the offending IP
holdtime=3600     # 3600 = 1 hr;  2700 = .45 hr; 1800 = .5 hr; 900 = .25 hr

cat /dev/null > $filePath/SRTII.txt
cat /dev/null > $filePath/SRTII.txt1
cat /dev/null > $filePath/SRTII.txt2
cat /dev/null > $filePath/SRTII.txt3

## delete MY_SYN_DROP recs that are past the hold time
while read line1; do                # delete MY_SYN_DROP recs that are past the hold time
      if [[ $(date +%s) -ge $(expr $(awk '{print $9}' <<< $line1) + $holdtime) ]]; then  # if logged rec time > holdtime
         varSRT=$(awk '{print $5}' <<< $line1)   # get logged IP address (ex: 79.0.0.0/8)
         iptables -D MY_SYN_DROP -s $varSRT -j DROP
         varSRT=${varSRT///8/}                   # remove /8 at end to find it for del in log
         sed -i "/$varSRT/d" $filePath/SRTII.log # processes, del from log file
      fi
done< $filePath/SRTII.log


iptables -L MY_SYN_DROP -n | grep all | awk '{print $4}' | cut -d' ' -f1 > $filePath/SRTII.txt3
lineno=0

while read line1; do                # delete MY_SYN_DROP recs that are past the hold time
      ((lineno++))

      if [[ ! $(cat $filePath/SRTII.log) =~ $line1 ]]; then
         iptables -D MY_SYN_DROP $lineno                    # delete ip from iptables
         SRTvar=$(sed -e 's/\/8/\\\/8/'<<< $line1)           # insert \ before /8
         sed -i "/$SRTvar/d" $filePath/SYN_AddrAttackII.txt  # remove line from file
      fi
done< $filePath/SRTII.txt3


## See if 2+ SYN_RECV records in netstat? (1 = random good SYN_RECV hit)
if [[ $(netstat -n -p TCP | grep SYN_RECV | wc -l) -le 1 ]]; then  # 2+ SYN_RECV records in netstat? (1 = random good SYN_RECV hit)
   exit 0                                                          # no
else
   netstat -vatnp > $filePath/SRTII.net

   if [[ $(cat SRTII.net | grep SYN_RECV | awk '{print $5}' | cut -d':' -f1,1 | sort | uniq -c | awk '{print $1}') -eq 1 ]]; then
      exit 0
   fi

   netstat -vatnp | grep SYN_RECV | awk '{print $5}' | cut -d'.' -f1,1 | sort | uniq -c > $filePath/SRTII.txt  # remove only one of same SYN_RECVs
   sed -i '/ 1 /d' $filePath/SRTII.txt   # get only one single SYN_RECVs
   awk '{print $2}' $filePath/SRTII.txt > $filePath/SRTII.txt1
   cat $filePath/SRTII.txt1 > $filePath/SRTII.txt
fi


if [ -e $filePath/SRTII.txt ] && [[ $(cat $filePath/SRTII.txt | wc -l) -gt 0 ]]; then  # if any IPs left after above comparison, then process
   ## iptables -A MY_SYN_DROP -s 104.0.0.0/1\8 -j DROP
   sed -i 's/^/iptables \-A MY_SYN_DROP \-s /' $filePath/SRTII.txt    # prepend to every new found rec
   sed -i 's/$/\.0\.0\.0\/8 -j DROP/' $filePath/SRTII.txt             # append to every new found rec

   while read line1; do                # save newfound recs to log with found date
         echo $line1 $(date "+%b.%d.%Y.%R %s") >> $filePath/SRTII.log
   done< $filePath/SRTII.txt

   iptables -L MY_SYN_DROP -n | grep all | awk '{print $4}' | cut -d' ' -f1 > $filePath/SRTII.txt2  # get former MY_SYN_DROP IPs
   sed -i 's/^/iptables \-A MY_SYN_DROP \-s /' $filePath/SRTII.txt2                                 # prepend to every former rec
   sed -i 's/$/ -j DROP/' $filePath/SRTII.txt2                                                      # append to every former rec

   cat $filePath/SRTII.txt $filePath/SRTII.txt2 | awk '!a[$0]++' > $filePath/SYN_AddrAttackII.txt  # concat old and new


   iptables -F MY_SYN_DROP   # flush past SYN_RECV IPs

   while read line1; do
         eval $line1
   done< $filePath/SYN_AddrAttackII.txt


   rm $filePath/SRTII.txt
   rm $filePath/SRTII.txt2
fi

rm $filePath/SRTII.txt
rm $filePath/SRTII.txt1
rm $filePath/SRTII.txt2
rm $filePath/SRTII.txt3

exit 0
```
