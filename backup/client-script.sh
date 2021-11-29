#!/bin/bash

RECIPIENT_PK='/Users/usr/Documents/ETH/AppliedSecLab/Project/git/credentials/ssh/backup/enc.pub'

ID_DIR = ''

FOLDERS_TO_BKP=(\
'/Users/usr/Documents/ETH/AppliedSecLab/Project/git/backup/test2' \
'/Users/usr/Documents/ETH/AppliedSecLab/Project/git/backup/test');

TMP_FOLDER_DIR="/Users/usr/Documents/ETH/AppliedSecLab/Project/git/backup";
TMP_FOLDER=$(mktemp -d ${TMP_FOLDER_DIR}/_XXXXXXXXXX);
# trap 'rm -rf $TMP_FOLDER' EXIT;

# Compression and encryption
for FOLDER in "${FOLDERS_TO_BKP[@]}"; do
    TAR_FN=$(echo "${TMP_FOLDER}")/$(echo "${FOLDER}".tar.gz | sed s!\/!! | sed s!\/!\-!g);
    tar -czf "${TAR_FN}" "${FOLDER}"
    age --armor -R "${RECIPIENT_PK}" -o "${TAR_FN}".age "${TAR_FN}"
    rm "${TAR_FN}"
done

# # transmission
# for ENC_FILE in "${TMP_FOLDER}"/*.age; do
#     scp -i "${ID_DIR}"/bkp-$(hostname)-usr "${ENC_FILE}" bkp-$(hostname)-usr@bkp.imovies.com:/
# done

# # decryption
# for ENC_FILE in "${TMP_FOLDER}"/*.age; do
#     DEC_FILE=$(basename "${ENC_FILE}" .tar.gz.age).tar.gz2
#     age --decrypt -i /Users/usr/Documents/ETH/AppliedSecLab/Project/git/credentials/ssh/bkp/enc -o "${TMP_FOLDER}/${DEC_FILE}" "${ENC_FILE}";
# done

