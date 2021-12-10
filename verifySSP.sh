#!/bin/bash

# Tested with ProVerif version 2.02
pv=proverif
title="ssp"
ssp_f="./model/ssp.pv"

# Derived names
attackdir="tableII-attacks-$title"

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
		new_f="$attackdir/tableII_row""${curr_num#0}""_column"$property"_attack-$title-$curr_num--$curr_name--$property.pdf"
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
    	copy_attack "$n" "$property"
		((n=n+1))
	done

	# Some space before the next entry
	echo ""
}

# Basic modules are implemented in "./model/ssp.pv".
# In this script, we model different cases in SSP by splicing different modules.
# This script reproduces the results in Table II in the paper.

# Verifying different BC pairing modes and mode combinations
echo "Verifying SSP security properties (A1 and A2). The runtime is for verifying the two properties."

echo "1. Verifying SSP just works mode"
prepare "01" "JW"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cjw()) | (step2pjw()) | (step3c()) | (step3p()) | (step4c()) | (step4p())" >> $tmp_f
analyze
echo ""

echo "2. Verifying SSP numeric comparison mode"
prepare "02" "NC"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "3. Verifying SSP passkey entry mode (central outputs and peripheral inputs)"
prepare "03" "PECoutPin"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpeout()) | (step2ppein()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecoutpin())" >> $tmp_f
analyze
echo ""

echo "4. Verifying SSP passkey entry mode (central inputs and peripheral outputs)"
prepare "04" "PECinPout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppeout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecinpout())" >> $tmp_f
analyze
echo ""

echo "5. Verifying SSP passkey entry mode (central and peripheral both input)"
prepare "05" "PECinPin"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppein()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin())" >> $tmp_f
analyze
echo ""

echo "6. Verifying SSP out-of-band mode (central outputs and peripheral inputs)"
prepare "06" "OOBCoutPin"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p())" >> $tmp_f
analyze
echo ""

echo "7. Verifying SSP out-of-band mode (central inputs and peripheral outputs)"
prepare "07" "OOBCinPout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p())" >> $tmp_f
analyze
echo ""

echo "8. Verifying SSP out-of-band mode (central and peripheral both input and output)"
prepare "08" "OOBCinoutPinout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) |(step4c()) | (step4p())" >> $tmp_f
analyze
echo ""

echo "9. Verifying SSP numeric comparison mode and passkey entry mode (central outputs and peripheral inputs) combination"
prepare "09" "NC_PECoutPin"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2cpeout()) | (step2ppein()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc()) | (userpecoutpin())" >> $tmp_f
analyze
echo ""

echo "10. Verifying SSP numeric comparison mode and passkey entry mode (central inputs and peripheral outputs) combination"
prepare "10" "NC_PECinPout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2cpein()) | (step2ppeout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc()) | (userpecinpout())" >> $tmp_f
analyze
echo ""

echo "11. Verifying SSP numeric comparison mode and passkey entry mode (both central and peripheral input) combination"
prepare "11" "NC_PECinPin"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2cpein()) | (step2ppein()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc()) | (userpebothin())" >> $tmp_f
analyze
echo ""

echo "12. Verifying SSP numeric comparison mode and out-of-band mode (central outputs and peripheral inputs) combination"
prepare "12" "NC_OOBCoutPin"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "13. Verifying SSP numeric comparison mode and out-of-band mode (central inputs and peripheral outputs) combination"
prepare "13" "NC_OOBCinPout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "14. Verifying SSP numeric comparison mode and out-of-band mode (central and peripheral both input and output) combination"
prepare "14" "NC_OOBCinoutPinout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cnc()) | (step2pnc()) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "15. Verifying SSP passkey entry mode (central outputs and peripheral inputs) and out-of-band mode (central outputs and peripheral inputs) combination"
prepare "15" "PECoutPin_OOBCoutPin"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpeout()) | (step2ppein()) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecoutpin())" >> $tmp_f
analyze
echo ""

echo "16. Verifying SSP passkey entry mode (central outputs and peripheral inputs) and out-of-band mode (central inputs and peripheral outputs) combination"
prepare "16" "PECoutPin_OOBCinPout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpeout()) | (step2ppein()) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecoutpin())" >> $tmp_f
analyze
echo ""

echo "17. Verifying SSP passkey entry mode (central outputs and peripheral inputs) and out-of-band mode (central and peripheral both input and output) combination"
prepare "17" "PECoutPin_OOBCinoutPinout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpeout()) | (step2ppein()) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecoutpin())" >> $tmp_f
analyze
echo ""

echo "18. Verifying SSP passkey entry mode (central inputs and peripheral outputs) and out-of-band mode (central outputs and peripheral inputs) combination"
prepare "18" "PECinPout_OOBCoutPin"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppeout()) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecinpout())" >> $tmp_f
analyze
echo ""

echo "19. Verifying SSP passkey entry mode (central inputs and peripheral outputs) and out-of-band mode (central inputs and peripheral outputs) combination"
prepare "19" "PECinPout_OOBCinPout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppeout()) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecinpout())" >> $tmp_f
analyze
echo ""

echo "20. Verifying SSP passkey entry mode (central inputs and peripheral outputs) and out-of-band mode (central and peripheral both input and output) combination"
prepare "20" "PECinPout_OOBCinoutPinout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppeout()) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpecinpout())" >> $tmp_f
analyze
echo ""

echo "21. Verifying SSP passkey entry mode (both central and peripheral input) and out-of-band mode (central outputs and peripheral inputs) combination"
prepare "21" "PECinPin_OOBCoutPin"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppein()) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin())" >> $tmp_f
analyze
echo ""

echo "22. Verifying SSP passkey entry mode (both central and peripheral input) and out-of-band mode (central inputs and peripheral outputs) combination"
prepare "22" "PECinPin_OOBCinPout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppein()) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin())" >> $tmp_f
analyze
echo ""

echo "23. Verifying SSP passkey entry mode (both central and peripheral input) and out-of-band mode (central and peripheral both input and output) combination"
prepare "23" "PECinPin_OOBCinoutPinout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2ppein()) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin())" >> $tmp_f
analyze
echo ""

echo "24. Verifying SSP numeric comparison mode, passkey entry mode (both central and peripheral input), and out-of-band mode (central outputs and peripheral inputs) combination"
prepare "24" "NC_PECinPin_OOBCoutPin"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2cnc()) | (step2pnc()) | (step2ppein()) | (step2coobout()) | (step2poobin()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "25. Verifying SSP numeric comparison mode, passkey entry mode (both central and peripheral input), and out-of-band mode (central inputs and peripheral outputs) combination"
prepare "25" "NC_PECinPin_OOBCinPout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2cnc()) | (step2pnc()) | (step2ppein()) | (step2coobin()) | (step2poobout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "26. Verifying SSP numeric comparison mode, passkey entry mode (both central and peripheral input), and out-of-band mode (central and peripheral both input and output) combination"
prepare "26" "NC_PECinPin_OOBCinoutPinout"
cat $ssp_f > $tmp_f
echo "(step1c(pri_C)) | (step1p(pri_P)) | (step2cpein()) | (step2cnc()) | (step2pnc()) | (step2ppein()) | (step2coobinout()) | (step2poobinout()) | (step3c()) | (step3p()) | (step4c()) | (step4p()) | (userpebothin()) | (user_nc())" >> $tmp_f
analyze
echo ""

echo "Verifying SSP finished."
