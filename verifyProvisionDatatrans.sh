#!/bin/bash

# Tested with ProVerif version 2.02
pv=proverif
title="provisionDatatrans"
prov_f="./model/provisionDatatrans.pv"

# Derived names
attackdir="tableVI-attacks-$title"

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
		new_f="$attackdir/tableVI_row$curr_num""_column"$property"_attack-$title-$curr_num--$curr_name--$property.pdf"
		cp $att_f $new_f
	fi
}

analyze () {
	time $pv $options $tmp_f | tee $out_f | grep RESULT

	n=1
	egrep "RESULT .*false|RESULT .*cannot be proved" $out_f | while read -r line ; do
		# property=$(echo $line | awk -F '[([-]' '{ print $2 }' | awk '{print $1}')
		if [[ $line == *"event(recv_prov(dhk)) ==> event(send_dev(dhk))"* ]]; then
			property="A3"
		fi
		if [[ $line == *"event(recv_dev(dhk)) ==> event(send_prov(dhk))"* ]]; then
			property="A4"
		fi
		if [[ $line == *"attacker(keys[])"* ]]; then
			property="C1"
		fi
		if [[ $line == *"attacker(p_complete[])"* ]]; then
			property="C2"
		fi
		if [[ $line == *"Non-interference keys"* ]]; then
			property="SS"
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

# Basic modules are implemented in "./model/provisionDatatrans.pv".
# In this script, we model Mesh provisioning together with Mesh data transmission.
# This script reproduces the results in Table VI in the paper.

# Verifying different authentication modes in Mesh provisioning
echo "Verifying Mesh provisioning and data transmission security properties (A3, A4, C1, C2, SS, C7, and C8). The runtime is for verifying the 7 properties."

echo "1. Verifying Mesh provisioning and data transmission as one protocol (OOB public key exchange and Output OOB authentication)"
prepare "1" "OOBpkOutputOOBAuth"
cat $prov_f > $tmp_f
echo "(invite_prov()) | (invite_dev()) | (pubkey_exchange_oob_prov(pri_P)) | (pubkey_exchange_oob_dev(pri_D)) | (auth_outputoob_prov()) | (auth_outputoob_dev()) | (send_data_prov()) | (recv_data_dev()) | (outputoob_user()) | (Mesh_stack_central()) | (Mesh_stack_peripheral()) | (Meshapp_central()) | (Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "2. Verifying Mesh provisioning and data transmission as one protocol (OOB public key exchange and Input OOB authentication)"
prepare "2" "OOBpkInputOOBAuth"
cat $prov_f > $tmp_f
echo "(invite_prov()) | (invite_dev()) | (pubkey_exchange_oob_prov(pri_P)) | (pubkey_exchange_oob_dev(pri_D)) | (auth_inputoob_prov()) | (auth_inputoob_dev()) | (send_data_prov()) | (recv_data_dev()) | (inputoob_user()) | (Mesh_stack_central()) | (Mesh_stack_peripheral()) | (Meshapp_central()) | (Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "3. Verifying Mesh provisioning and data transmission as one protocol (OOB public key exchange and Static OOB authentication)"
prepare "3" "OOBpkStaticOOBAuth"
cat $prov_f > $tmp_f
echo "(invite_prov()) | (invite_dev()) | (pubkey_exchange_oob_prov(pri_P)) | (pubkey_exchange_oob_dev(pri_D)) | (auth_staticoob_prov(static_oobdata)) | (auth_staticoob_dev(static_oobdata)) | (send_data_prov()) | (recv_data_dev()) | (Mesh_stack_central()) | (Mesh_stack_peripheral()) | (Meshapp_central()) | (Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "4. Verifying Mesh provisioning and data transmission as one protocol (OOB public key exchange and No OOB authentication)"
prepare "4" "OOBpkNoOOBAuth"
cat $prov_f > $tmp_f
echo "(invite_prov()) | (invite_dev()) | (pubkey_exchange_oob_prov(pri_P)) | (pubkey_exchange_oob_dev(pri_D)) | (auth_staticoob_prov(zero)) | (auth_staticoob_dev(zero)) | (send_data_prov()) | (recv_data_dev()) | (Mesh_stack_central()) | (Mesh_stack_peripheral()) | (Meshapp_central()) | (Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "5. Verifying Mesh provisioning and data transmission as one protocol (NoOOB public key exchange and Output OOB authentication)"
prepare "5" "NoOOBpkOutputOOBAuth"
cat $prov_f > $tmp_f
echo "(invite_prov()) | (invite_dev()) | (pubkey_exchange_noob_prov(pri_P)) | (pubkey_exchange_noob_dev(pri_D)) | (auth_outputoob_prov()) | (auth_outputoob_dev()) | (send_data_prov()) | (recv_data_dev()) | (outputoob_user()) | (Mesh_stack_central()) | (Mesh_stack_peripheral()) | (Meshapp_central()) | (Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "6. Verifying Mesh provisioning and data transmission as one protocol (NoOOB public key exchange and Input OOB authentication)"
prepare "6" "NoOOBpkInputOOBAuth"
cat $prov_f > $tmp_f
echo "(invite_prov()) | (invite_dev()) | (pubkey_exchange_noob_prov(pri_P)) | (pubkey_exchange_noob_dev(pri_D)) | (auth_inputoob_prov()) | (auth_inputoob_dev()) | (send_data_prov()) | (recv_data_dev()) | (inputoob_user()) | (Mesh_stack_central()) | (Mesh_stack_peripheral()) | (Meshapp_central()) | (Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "7. Verifying Mesh provisioning and data transmission as one protocol (NoOOB public key exchange and Static OOB authentication)"
prepare "7" "NoOOBpkStaticOOBAuth"
cat $prov_f > $tmp_f
echo "(invite_prov()) | (invite_dev()) | (pubkey_exchange_noob_prov(pri_P)) | (pubkey_exchange_noob_dev(pri_D)) | (auth_staticoob_prov(static_oobdata)) | (auth_staticoob_dev(static_oobdata)) | (send_data_prov()) | (recv_data_dev()) | (Mesh_stack_central()) | (Mesh_stack_peripheral()) | (Meshapp_central()) | (Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "8. Verifying Mesh provisioning and data transmission as one protocol (NoOOB public key exchange and No OOB authentication)"
prepare "8" "NoOOBpkNoOOBAuth"
cat $prov_f > $tmp_f
echo "(invite_prov()) | (invite_dev()) | (pubkey_exchange_noob_prov(pri_P)) | (pubkey_exchange_noob_dev(pri_D)) | (auth_staticoob_prov(zero)) | (auth_staticoob_dev(zero)) | (send_data_prov()) | (recv_data_dev()) | (Mesh_stack_central()) | (Mesh_stack_peripheral()) | (Meshapp_central()) | (Meshapp_peripheral())" >> $tmp_f
analyze
echo ""

echo "Verifying Mesh provisioning finished."
