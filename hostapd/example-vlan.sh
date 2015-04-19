#! /bin/sh

# Each command might be called multiple times.
# Exit with non-zero to indicate that bridge/port already exists or cmd is unimplemented.

set -e

CMD="$1"

case "${CMD}" in
	"br_name")
		REQNAME="$2"
		TAGGED="$3"
		VID="$4"
		if [ -n "${REQNAME}" ]; then
			echo "${REQNAME}${VID}"
			exit 0;
		fi
		if [ -n "${TAGGED}" ]; then
			echo "${TAGGED}${VID}"
			exit 0;
		fi
		echo "brvlan${VID}"
		exit 0;
		;;
	"br_addbr")
		BRNAME="$2"
		VID="$3"
		brctl addbr "${BRNAME}"
		ifconfig "${BRNAME}" up
		;;
	"br_addif")
		# might be called multiple times such that vlan cfg adds up
		BRNAME="$2"
		PORT="$3"
		VLANMODE="$4" # tagged or untagged or empty
		VID="$5" # only set for VLANMODE=tagged or untagged
		if [ "${VLANMODE}" = "tagged" ]; then
			ip link add link "${PORT}" name "${PORT}.${VID}" type vlan id "${VID}"
			ifconfig "${PORT}.${VID}" up
			brctl addif "${BRNAME}" "${PORT}.${VID}"
		else
			ifconfig "${PORT}" up
			brctl addif "${BRNAME}" "${PORT}"
		fi
		;;
	"br_delbr")
		BRNAME="$2"
		VID="$3"
		ifconfig "${BRNAME}" down
		brctl delbr "${BRNAME}"
		;;
	"br_delif")
		# might be called multiple times for each vlan configured before
		BRNAME="$2"
		PORT="$3"
		VLANMODE="$4" # tagged or untagged or empty
		VID="$5" # only set for VLANMODE=tagged or untagged
		if [ "${VLANMODE}" = "tagged" ]; then
			ifconfig "${PORT}.${VID}" down
			brctl delif "${BRNAME}" "${PORT}.${VID}"
			ip link del "${PORT}.${VID}"
		else
			ifconfig "${PORT}" down
			brctl delif "${BRNAME}" "${PORT}"
		fi
		;;
	*)
		exit 1;
		;;
esac;

exit 0;
