#!/bin/env zsh
set -e

SAVEIFS=$IFS
IFS=$'\n'
files=($(ls | grep pcap))
IFS=$SAVEIFS

for ((i = 0; i < ${#files[@]}; i++)); do
  f="${files[$i + 1]}"
  echo "file $(($i + 1))/${#files[@]}\t$f"
  mkdir -p "${f%.*}"

  SAVEIFS=$IFS
  IFS=$'\n'
  ips=($(tshark -r "$f" -c 100000 -Tfields -e ip.dst | rg -v , | sort | uniq))
  IFS=$SAVEIFS

  for ((j = 0; j < ${#ips[@]}; j++)); do
    ip="${ips[$j + 1]}"
    echo -n "$(($j + 1))/${#ips[@]}\t\t$ip             \r"

    if [ "${f%.*}" != "$ip" ]; then
      SSHARK_JSON_FILE="${f%.*}/$ip.json" SSHARK_IP_ADD="$ip" speedshark "$f" "${f%.*}/$ip.pcapng"
      #echo "in: $f" "out: ${f%.*}/$ip.pcapng" "json: ${f%.*}/$ip.json" "ip: $ip"
    fi
  done
  echo
done
