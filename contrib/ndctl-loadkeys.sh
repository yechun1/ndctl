#!/bin/bash -Ex

# This script assumes a single master key for all DIMMs

key_path=/etc/ndctl/keys
tpmh_path="$key_path"/tpm.handle
key_type=""
tpm_handle=""
id=""

if [ -f $tpmh_path ]; then
	key_type=trusted
	tpm_handle="keyhandle=$(cat $tpmh_path)"
else
	key_type=user
fi

if ! keyctl search @u "$key_type" nvdimm-master; then
	keyctl add "$key_type" nvdimm-master "load $(cat $key_path/nvdimm-master.blob) $tpm_handle" @u > /dev/null
fi

for file in "$key_path"/nvdimm_*; do
	id="$(cut -d'_' -f2 <<< "${file##*/}")"
	keyctl add encrypted nvdimm:"$id" "load $(cat "$file")" @u
done
