#!/bin/bash


HNAME='ca'


FOLDERS_TO_BKP=(\
'/Users/usr/Documents/ETH/AppliedSecLab/Project/git/backup/test2' \
'/Users/usr/Documents/ETH/AppliedSecLab/Project/git/backup/test');



TMP_FOLDER_DIR="/root/backup/";
ENC_KEY='/root/backup/enc.pub'
ID_DIR="/root/.ssh"
TMP_FOLDER=$(mktemp -d ${TMP_FOLDER_DIR}/_XXXXXXXXXX);

trap 'rm -rf $TMP_FOLDER' EXIT;

# Compression and encryption
for FOLDER in "${FOLDERS_TO_BKP[@]}"; do
    TAR_FN=$(echo "${TMP_FOLDER}")/$(date "+%Y-%m-%d_%H:%M_")$(echo "${FOLDER}".tar.gz | sed s!\/!! | sed s!\/!\-!g);
    tar -czf "${TAR_FN}" "${FOLDER}"
    age --armor -R "${ENC_KEY}" -o "${TAR_FN}".age "${TAR_FN}"
    rm "${TAR_FN}"
done

# creating instructions for sftp
TMP_BATCHFILE="${TMP_FOLDER}"/batch.batch
touch "${TMP_BATCHFILE}";
echo "put *.age backups/" > "${TMP_BATCHFILE}";

# transfer files
sftp -i "${ID_DIR}"/bkp-"${HNAME}" -b "${TMP_BATCHFILE}" bkp-"${HNAME}"@bkp.imovies.com;

