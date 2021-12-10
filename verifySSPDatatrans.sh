#!/bin/bash

# Tested with ProVerif version 2.02
pv=proverif
title="sspDatatrans"
sspdata_f="./model/sspDatatrans.pv"

# Derived names
attackdir="tableV-attacks-$title"

# Ensure attacks directory exists
mkdir -p $attackdir

prepare () {
	curr_num="$1"
	curr_name="$2"
	outdir="results-$title-$1-$2"
	mkdir -p $outdir
	tmp_f="$outdir/model.pv"
	out_f="$outdir/output.txt"
	options="-html $outdir"
}

copy_attack () {
	att_f="$outdir/trace$1.pdf"
	property="$2"
	if test -f "$att_f"; then
		new_f="$attackdir/tableV_row$curr_num""_column"$property"_attack-$title-$curr_num--$curr_name--$property.pdf"
		cp $att_f $new_f
	fi
}

analyze () {
	time $pv $options $tmp_f | tee $out_f | grep RESULT

	n=1
	grep "RESULT.*false" $out_f | while read -r line ; do
		# property=$(echo $line | awk -F '[([]' '{ print $2 }')
		if [[ $line == *"event(recv_central(dhk)) ==> event(send_peripheral(dhk))"* ]]; then
			property="A1"
		fi
		if [[ $line == *"event(recv_peripheral(dhk)) ==> event(send_central(dhk))"* ]]; then
			property="A2"
		fi
		if [[ $line == *"attacker(BCreq[])"* ]]; then
			property="C3"
		fi
		if [[ $line == *"attacker(BCrsp[])"* ]]; then
			property="C4"
		fi
		if [[ $line == *"attacker(BLEreq[])"* ]]; then
			property="C5"
		fi
		if [[ $line == *"attacker(BLErsp[])"* ]]; then
			property="C6"
		fi
    	copy_attack "$n" "$property"
		((n=n+1))
	done

	# Some space before the next entry
	echo ""
}

# Verifying different BC/BLE pairing modes and data transmission at once.
# Basic modules are implemented in "./model/sspDatatrans.pv".
# In this script, we model different cases in SSP together with data transmission in BC/BLE by splicing different modules.
# This script reproduces the results in Table V in the paper.

# No need to verify mode combinations that include a vulnerable pairing mode.
echo "Verifying SSP and data transmission security properties at once (A1, A2, C3, C4, C5, and C6). The runtime is for verifying the six properties."

echo "1. Verifying SSP and data transmission as one protocol, just works mode"
prepare "01" "JW"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cjw()) | (step2pjw()) | (step3c()) | (step3p()) | (step4c()) | (step4p())" >> $tmp_f
analyze
echo ""

echo "2. Verifying SSP and data transmission as one protocol, numeric comparison mode"
prepare "02" "NC"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "3. Verifying SSP and data transmission as one protocol, passkey entry mode (central outputs and peripheral inputs)"
prepare "03" "PECoutPin"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpeout()) | (step2ppein()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecoutpin())" >> $tmp_f
analyze
echo ""

echo "4. Verifying SSP and data transmission as one protocol, passkey entry mode (central inputs and peripheral outputs)"
prepare "04" "PECinPout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppeout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecinpout())" >> $tmp_f
analyze
echo ""

echo "5. Verifying SSP and data transmission as one protocol, passkey entry mode (central and peripheral both input)"
prepare "05" "PECinPin"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppein()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin())" >> $tmp_f
analyze
echo ""

echo "6. Verifying SSP and data transmission as one protocol, out-of-band mode (central outputs and peripheral inputs)"
prepare "06" "OOBCoutPin"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p())" >> $tmp_f
analyze
echo ""

echo "7. Verifying SSP and data transmission as one protocol, out-of-band mode (central inputs and peripheral outputs)"
prepare "07" "OOBCinPout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p())" >> $tmp_f
analyze
echo ""

echo "8. Verifying SSP and data transmission as one protocol, out-of-band mode (central and peripheral both input and output)"
prepare "08" "OOBCinoutPinout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) |(step4c()) | (step4p())" >> $tmp_f
analyze
echo ""

echo "9. Verifying SSP and data transmission as one protocol, numeric comparison mode and passkey entry mode (central outputs and peripheral inputs)combination"
prepare "09" "NC_PECoutPin"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2cpeout()) | (step2ppein()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc()) | (userpecoutpin())" >> $tmp_f
analyze
echo ""

echo "10. Verifying SSP and data transmission as one protocol, numeric comparison mode and passkey entry mode (central inputs and peripheral outputs) combination"
prepare "10" "NC_PECinPout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2cpein()) | (step2ppeout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc()) | (userpecinpout())" >> $tmp_f
analyze
echo ""

echo "11. Verifying SSP and data transmission as one protocol, numeric comparison mode and passkey entry mode (both central and peripheral input) combination"
prepare "11" "NC_PECinPin"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2cpein()) | (step2ppein()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc()) | (userpebothin())" >> $tmp_f
analyze
echo ""

echo "12. Verifying SSP and data transmission as one protocol, numeric comparison mode and out-of-band mode (central outputs and peripheral inputs) combination"
prepare "12" "NC_OOBCoutPin"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "13. Verifying SSP and data transmission as one protocol, numeric comparison mode and out-of-band mode (central inputs and peripheral outputs) combination"
prepare "13" "NC_OOBCinPout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "14. Verifying SSP and data transmission as one protocol, numeric comparison mode and out-of-band mode (central and peripheral both input and output) combination"
prepare "14" "NC_OOBCinoutPinout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "15. Verifying SSP and data transmission as one protocol, passkey entry mode (central outputs and peripheral inputs) and out-of-band mode (central outputs and peripheral inputs) combination"
prepare "15" "PECoutPin_OOBCoutPin"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpeout()) | (step2ppein()) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecoutpin())" >> $tmp_f
analyze
echo ""

echo "16. Verifying SSP and data transmission as one protocol, passkey entry mode (central outputs and peripheral inputs) and out-of-band mode (central inputs and peripheral outputs) combination"
prepare "16" "PECoutPin_OOBCinPout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpeout()) | (step2ppein()) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecoutpin())" >> $tmp_f
analyze
echo ""

echo "17. Verifying SSP and data transmission as one protocol, passkey entry mode (central outputs and peripheral inputs) and out-of-band mode (central and peripheral both input and output) combination"
prepare "17" "PECoutPin_OOBCinoutPinout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpeout()) | (step2ppein()) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecoutpin())" >> $tmp_f
analyze
echo ""

echo "18. Verifying SSP and data transmission as one protocol, passkey entry mode (central inputs and peripheral outputs) and out-of-band mode (central outputs and peripheral inputs) combination"
prepare "18" "PECinPout_OOBCoutPin"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppeout()) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecinpout())" >> $tmp_f
analyze
echo ""

echo "19. Verifying SSP and data transmission as one protocol, passkey entry mode (central inputs and peripheral outputs) and out-of-band mode (central inputs and peripheral outputs) combination"
prepare "19" "PECinPout_OOBCinPout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppeout()) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecinpout())" >> $tmp_f
analyze
echo ""

echo "20. Verifying SSP and data transmission as one protocol, passkey entry mode (central inputs and peripheral outputs) and out-of-band mode (central and peripheral both input and output) combination"
prepare "20" "PECinPout_OOBCinoutPinout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppeout()) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecinpout())" >> $tmp_f
analyze
echo ""

echo "21. Verifying SSP and data transmission as one protocol, passkey entry mode (both central and peripheral input) and out-of-band mode (central outputs and peripheral inputs) combination"
prepare "21" "PECinPin_OOBCoutPin"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppein()) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin())" >> $tmp_f
analyze
echo ""

echo "22. Verifying SSP and data transmission as one protocol, passkey entry mode (both central and peripheral input) and out-of-band mode (central inputs and peripheral outputs) combination"
prepare "22" "PECinPin_OOBCinPout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppein()) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin())" >> $tmp_f
analyze
echo ""

echo "23. Verifying SSP and data transmission as one protocol, passkey entry mode (both central and peripheral input) and out-of-band mode (central and peripheral both input and output) combination"
prepare "23" "PECinPin_OOBCinoutPinout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppein()) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin())" >> $tmp_f
analyze
echo ""

echo "24. Verifying SSP and data transmission as one protocol, numeric comparison mode, passkey entry mode (both central and peripheral input), and out-of-band mode (central outputs and peripheral inputs) combination"
prepare "24" "NC_PECinPin_OOBCoutPin"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2cnc()) | (step2pnc()) | (step2ppein()) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "25. Verifying SSP and data transmission as one protocol, numeric comparison mode, passkey entry mode (both central and peripheral input), and out-of-band mode (central inputs and peripheral outputs) combination"
prepare "25" "NC_PECinPin_OOBCinPout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2cnc()) | (step2pnc()) | (step2ppein()) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "26. Verifying SSP and data transmission as one protocol, numeric comparison mode, passkey entry mode (both central and peripheral input), and out-of-band mode (central and peripheral both input and output) combination"
prepare "26" "NC_PECinPin_OOBCinoutPinout"
cat $sspdata_f > $tmp_f
echo "(BC_stack_central) | (BC_stack_peripheral) | (BCapp_central) | (BCapp_peripheral) | (BLE_stack_central) | (BLE_stack_peripheral) | (BLEapp_central) | (BLEapp_peripheral) | (step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2cnc()) | (step2pnc()) | (step2ppein()) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "Verifying SSP and data transmission at once finished."
