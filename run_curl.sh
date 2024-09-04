#!/bin/bash

#check if the URL was provided as an argument
if [ -z "$1" ]; then
    echo "Provide with URL: $0 <url>"
    exit 1
fi

#use the first argument as the target URL
url=$1

#writing output to times.txt
outfile="times.txt" > $outfile

#for loop to repeat command 1000 times
for i in {1..1000}
do
    #execute curl command and grep the 'real' part. extracr the second column as that has the time.
    (time curl "$url") 2>&1 | grep real | awk '{print $2}' >> $outfile
done

