#!/bin/bash

echo "Verify all protocols. It may take up to 5 hours to finish."
sleep 3

sh ./verifySSP.sh
echo ""

sh ./verifyProvision.sh
echo ""

sh ./verifyDatatrans.sh
echo ""

sh ./verifySSPDatatrans.sh
echo ""

sh ./verifyProvisionDatatrans.sh