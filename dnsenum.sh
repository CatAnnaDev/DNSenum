#!/bin/bash

MY_PATH="`dirname \"$0\"`"
MY_PATH="`( cd \"$MY_PATH\" && pwd )`"
DNSFILE="${MY_PATH}/wordlist/subdomain.txt"
DNSSERVER=""
DOMAIN="0"
HTTPCHECK=0
RESULT="0"
VIRUSTOTAL=0
SHODAN="apikey-here"

source ${MY_PATH}/inc/bash_colors.sh

echo -en "\n+\n"
echo "+ DNSenum by CatAnnaDev: https://github.com/CatAnnaDev/DNSenum"
while getopts :hcvd:n:r:s: OPTION; do
	case $OPTION in
		d)
			echo "+ Dns Enumeration for domain ${OPTARG}"
			DOMAIN=${OPTARG}
		;;
		f)
			echo "+ Using file ${OPTARG}"
			DNSFILE=${OPTARG}
		;;
		n)
			echo "+ Using DNS Server ${OPTARG}"
			DNSSERVER=" @${OPTARG}"
		;;
		c)
			HTTPCHECK=1
		;;
		r)
			echo "+ Filter result: ${OPTARG}"
			RESULT="${OPTARG}"
		;;
		h)
			echo "+ Usage: $0 -d <domain> [-f <file] [-n <dns server>] [-c]"
			echo "+"
			echo "+ -d <domain>      Domain name to test"
			echo "+ -f <file>        Subdomain list file to use for test (default subdomain.txt)"
			echo "+ -n <dns server>  DNS Server to use for query"
			echo "+ -c               Check for HTTP Server banner"
			echo "+ -r <result>      Show only result that match <result>"
			echo -en "+\n\n"
			exit 0
		;;
	esac
done

if [ ${DOMAIN} = "0" ]; then
	echo "+ Usage $0 -d example.com [-f subdomain-list.txt]"
	echo "+ Full help: $0 -h "
	echo "+"
	exit 0
fi

REGEX="(.+)[[:space:]]+([A-Z0-9]+)[[:space:]]+([a-zA-Z0-9\.\-]+)"
RANDOMSD=$(perl -pe 'tr/A-Za-z0-9//dc;' < /dev/urandom | head -c 20; echo)
WILDCARD=RANDOMSD
DNSTEST=$(dig +noall +answer +nottlid +nocl ${RANDOMSD}.${DOMAIN}${DNSSERVER} | head -1)
STARTRES=$(dig +noall +answer +nottlid +nocl ${DOMAIN}${DNSSERVER} | head -1)


if [[ ${DNSTEST} =~ $REGEX ]]; then
	WILDCARD="${BASH_REMATCH[3]}"
	echo "+ Wildcard resolution is enabled on this domain (${WILDCARD})"
	echo "+ checking for others results != ${WILDCARD} ..."
fi

echo "+"
echo ""

clr_red "+"
clr_red "+ Start enumeration from file..."
clr_red "+"
if [[ ${STARTRES} =~ $REGEX ]]; then
	if [ ${RESULT} = "0" ] || [ ${RESULT} = ${BASH_REMATCH[3]} ]; then
		if [ $HTTPCHECK -eq 1 ]; then
			echo -en "trying to connect to http://${DOMAIN} ..."
			CURL=$(curl -m 5 -s -I --connect-timeout 2 "http://${DOMAIN}" | grep -i "server:" | sed -e 's/Server: //g')
			echo -en "\033[99D"
			echo -en "\033[K"
		fi
		printf "%30b | %-20b | %-40b | %-10b" "\033[0;32m${DOMAIN}\033[0m" "\033[1;34m${BASH_REMATCH[2]}\033[0m" "${BASH_REMATCH[3]}" "${CURL}"
		echo ""
	fi
fi

while read line; do
	TMP=${line}.${DOMAIN}
	URL_RM_DOT=${TMP//../.}
	URLEND=${URL_RM_DOT/./}
	DNSRES=$(dig +noall +answer +nottlid +nocl ${URLEND}${DNSSERVER} | head -1)

	echo -en "${DOMAIN} trying ${line} ..."

	if [[ ${DNSRES} =~ $REGEX ]]; then
		RES="${BASH_REMATCH[3]}"
		if [[ "${WILDCARD}" == "${RES}" ]]; then
			echo "discard ${RES}"
			echo -en "\033[K"
			echo -en "\033[99D"
		else
			echo -en "\033[99D"
			echo -en "\033[K"

			if [ ${RESULT} == "0" ] || [ ${RESULT} == ${BASH_REMATCH[3]} ]; then
				if [ $HTTPCHECK -eq 1 ]; then
					URL="http://${URLEND}"
					echo -en "trying to connect to ${URL} ..."
					CURL=$(curl -m5 -s -I --connect-timeout 2 ${URL} | grep -i "server:" | sed -e 's/Server: //g')
					echo -en "\033[99D"
					echo -en "\033[K"
				fi
				printf "%30b | %-20b | %-40b | %-10b" "\033[0;32m${line}\033[0m" "\033[1;34m${BASH_REMATCH[2]}\033[0m" "${BASH_REMATCH[3]}" "${CURL}"
				echo ""
			fi
		fi
	else
		echo -en "\033[K"
		echo -en "\033[99D"
	fi
done<$DNSFILE
