#!/bin/bash
set -e

if [[ $(hostname) == "thinkpad" ]]; then
	make -C "$(dirname "$0")/../../src" remote-run
	for i in 128 129 130; do
		scp "$0" root@172.16.48.${i}:
	done
	for i in 128 129 130; do
		konsole --new-tab -e ssh -t root@172.16.48.${i} "./$(basename "$0")"
	done
	exit
fi

# perf top -U --dsos '[wireguard]'

tmux new-session -s bigtest -d
tmux new-window -n "server 6000" -t bigtest "iperf3 -p 6000 -s"
tmux new-window -n "server 6001" -t bigtest "iperf3 -p 6001 -s"
sleep 5
me=$(ip -o -4 address show dev wg0 | sed 's/.*inet \([^ ]*\)\/.*/\1/' | cut -d . -f 4)
for i in 1 2 3; do
	[[ $i == $me ]] && continue
	[[ $me == "1" ]] && port=6000
	[[ $me == "3" ]] && port=6001
	[[ $me == "2" && $i == "1" ]] && port=6000
	[[ $me == "2" && $i == "3" ]] && port=6001
	tmux new-window -n "client 192.168.2.${i}" -t bigtest "iperf3 -n 300000G -i 1 -p $port -c 192.168.2.${i}"
done
tmux attach -t bigtest
