#!/bin/bash


while :
do
  if [[ $(ps -ef | grep Virus_class.py | grep -v grep) ]];then
    continue
  else
    sleep 1
    echo "start .py"
    echo "1">>watch.txt
    python Virus_class.py
  fi
  sleep 1
done

