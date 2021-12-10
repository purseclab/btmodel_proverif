#!/bin/bash

# Tested with ProVerif version 2.02
pv=proverif
title="dataTransmission"
data_f="./model/dataTransmission.pv"

# Derived names
attackdir="tableIV-attacks-$title"

# Ensure attacks directory exists
mkdir -p $attackdir

# prepare("01" "Subtitle") sets up analysis for set "results-TITLE-01-Subtitle" and a corresponding directory
prepare () {
	curr_num="$1"
	curr_name="$2"
	outdir="results-$title-$1-$2"
	mkdir -p $outdir
	tmp_f="$outdir/model.pv"
	out_f="$outdir/output.txt"
	options="-html $outdir"
}

# When given the -html option, ProVerif also produces the (not very meaningfully named) trace1.pdf, trace2.pdf, etc. This function copies them to the relevant attacks directory.
copy_attack () {
	att_f="$outdir/trace$1.pdf"
	property="$2"
	if test -f "$att_f"; then
		new_f="$attackdir/tableIV_row""${curr_num#0}""_column"$property"_attack-$title-$curr_num--$curr_name--$property.pdf"
		cp $att_f $new_f
	fi
}

# Analyze the current $tmp_f file and store the results; afterwards, copy out the attack traces corresponding to any falsified properties.
analyze () {
	time $pv $options $tmp_f | tee $out_f | grep RESULT

	n=1
	grep "RESULT.*false" $out_f | while read -r line ; do
		# property=$(echo $line | awk -F '[([]' '{ print $2 }')
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
		if [[ $line == *"attacker(Meshreq[])"* ]]; then
			property="C7"
		fi
		if [[ $line == *"attacker(Meshrsp[])"* ]]; then
			property="C8"
		fi
    	copy_attack "$n" "$property"
		((n=n+1))
	done

	# Some space before the next entry
	echo ""
}

# Basic modules are implemented in "./model/dataTransmission.pv".
# In this script, we model different cases in the data transmission phase by splicing different modules.
# This script reproduces the results in Table IV in the paper.

# Verifying different connection scenarios in data transmission
echo "Verifying data transmission security properties (C3, C4, C5, C6, C7, and C8). The runtime is for verifying the six properties."

echo "1. BC connections only, device NOT compromised (concurrent execution)"
prepare "01" "BC-noncompr"
cat $data_f > $tmp_f
echo "(!BC_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral) | (!BLE_stack_peripheral) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BCapp_peripheral)" >> $tmp_f
analyze
echo ""

echo "2. BC connections only, device compromised (concurrent execution)"
prepare "02" "BC-compr"
cat $data_f > $tmp_f
echo "(!BC_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral_compromised) | (!BLE_stack_peripheral_compromised) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral_compromised()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BCapp_peripheral)" >> $tmp_f
analyze
echo ""


echo "3. BLE connections only, device NOT compromised (reactive authentication, concurrent execution)"
prepare "03" "BLE-noncompr-reactive"
cat $data_f > $tmp_f
echo "(!BLE_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central_insecure) | (!BC_stack_peripheral) | (!BLE_stack_peripheral) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BLEapp_peripheral)" >> $tmp_f
analyze
echo ""

echo "4. BLE connections only, device NOT compromised (proactive authenticationcon, current execution)"
prepare "04" "BLE-noncompr-proactive"
cat $data_f > $tmp_f
echo "(!BLE_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral) | (!BLE_stack_peripheral) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BLEapp_peripheral)" >> $tmp_f
analyze
echo ""

echo "5. BLE connections only, device compromised (concurrent execution)"
prepare "05" "BLE-compr"
cat $data_f > $tmp_f
echo "(!BLE_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral_compromised) | (!BLE_stack_peripheral_compromised) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral_compromised()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BLEapp_peripheral)" >> $tmp_f
analyze
echo ""

echo "6. Mesh connections only, device NOT compromised (concurrent execution)"
prepare "06" "Mesh-noncompr"
cat $data_f > $tmp_f
echo "(!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral) | (!BLE_stack_peripheral) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "7. Mesh connections only, device compromised (concurrent execution)"
prepare "07" "Mesh-compr"
cat $data_f > $tmp_f
echo "(!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral_compromised) | (!BLE_stack_peripheral_compromised) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral_compromised()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "8. BC and BLE connections, device NOT compromised, pairing via BC (concurrent execution)"
prepare "08" "BC_BLE-BC_pairing-noncompr"
cat $data_f > $tmp_f
echo "(!BC_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral) | (!BLE_stack_peripheral) | (!Mesh_secure_provisioning) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral()) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BCapp_peripheral) | (!BLEapp_peripheral)" >> $tmp_f
analyze
echo ""

echo "9. BC and BLE connections, device compromised, pairing via BC (concurrent execution)"
prepare "09" "BC_BLE-BC_pairing-compr"
cat $data_f > $tmp_f
echo "(!BC_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral_compromised) | (!BLE_stack_peripheral_compromised) | (!Mesh_secure_provisioning) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral_compromised()) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BCapp_peripheral) | (!BLEapp_peripheral)" >> $tmp_f
analyze
echo ""

echo "10. BC and BLE connections, device NOT compromised, pairing via BLE (concurrent execution)"
prepare "10" "BC_BLE-BLE_pairing-noncompr"
cat $data_f > $tmp_f
echo "(!BLE_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral) | (!BLE_stack_peripheral) | (!Mesh_secure_provisioning) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral()) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BLEapp_peripheral) | (!BCapp_peripheral)" >> $tmp_f
analyze
echo ""

echo "11. BC and BLE connections, device compromised, pairing via BLE (concurrent execution)"
prepare "11" "BC_BLE-BLE_pairing-compr"
cat $data_f > $tmp_f
echo "(!BLE_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral_compromised) | (!BLE_stack_peripheral_compromised) | (!Mesh_secure_provisioning) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral_compromised()) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BLEapp_peripheral) | (!BCapp_peripheral)" >> $tmp_f
analyze
echo ""

echo "12. BC and Mesh connections, device NOT compromised (concurrent execution)"
prepare "12" "BC_Mesh-noncompr"
cat $data_f > $tmp_f
echo "(!BC_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral) | (!BLE_stack_peripheral) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BCapp_peripheral) | (!Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "13. BC and Mesh connections, device compromised (concurrent execution)"
prepare "13" "BC_Mesh-compr"
cat $data_f > $tmp_f
echo "(!BC_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral_compromised) | (!BLE_stack_peripheral_compromised) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral_compromised()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BCapp_peripheral) | (!Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "14. BLE and Mesh connections, device NOT compromised (concurrent execution)"
prepare "14" "BLE_Mesh-noncompr"
cat $data_f > $tmp_f
echo "(!BLE_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral) | (!BLE_stack_peripheral) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BLEapp_peripheral) | (!Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "15. BLE and Mesh connections, device compromised (concurrent execution)"
prepare "15" "BLE_Mesh-compr"
cat $data_f > $tmp_f
echo "(!BLE_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral_compromised) | (!BLE_stack_peripheral_compromised) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral_compromised()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BLEapp_peripheral) | (!Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "16. BC, BLE, and Mesh connections, device NOT compromised, pairing via BC (concurrent execution)"
prepare "16" "BC_BLE_Mesh-BC_pairing-noncompr"
cat $data_f > $tmp_f
echo "(!BC_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral) | (!BLE_stack_peripheral) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BCapp_peripheral) | (!BLEapp_peripheral) | (!Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "17. BC, BLE, and Mesh connections, device compromised, pairing via BC (concurrent execution)"
prepare "17" "BC_BLE_Mesh-BC_pairing-compr"
cat $data_f > $tmp_f
echo "(!BC_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral_compromised) | (!BLE_stack_peripheral_compromised) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral_compromised()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BCapp_peripheral) | (!BLEapp_peripheral) | (!Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "18. BC, BLE, and Mesh connections, device NOT compromised, pairing via BLE (concurrent execution)"
prepare "18" "BC_BLE_Mesh-BLE_pairing-noncompr"
cat $data_f > $tmp_f
echo "(!BLE_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral) | (!BLE_stack_peripheral) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BLEapp_peripheral) | (!BCapp_peripheral) | (!Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "19. BC, BLE, and Mesh connections, device compromised, pairing via BLE (concurrent execution)"
prepare "19" "BC_BLE_Mesh-BLE_pairing-compr"
cat $data_f > $tmp_f
echo "(!BLE_secure_pairing) | (!BC_stack_central) | (!BLE_stack_central) | (!BC_stack_peripheral_compromised) | (!BLE_stack_peripheral_compromised) | (!Mesh_stack_central()) | (!Mesh_stack_peripheral_compromised()) | (!Mesh_secure_provisioning) | (!BLEapp_central) | (!BCapp_central) | (!Meshapp_central()) | (!BLEapp_peripheral) | (!BCapp_peripheral) | (!Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "Verifying data transmission finished."
