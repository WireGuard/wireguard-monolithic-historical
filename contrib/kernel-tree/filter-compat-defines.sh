#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.

silent=0
level=0
ifs=( )

while IFS= read -r line; do
	if [[ $line =~ ^[[:space:]]*(#if.*) ]]; then
		ifs[level++]=0
		if [[ ${BASH_REMATCH[1]} == "#ifndef COMPAT_CANNOT_"* ]]; then
			ifs[level-1]=-1
			continue
		elif [[ ${BASH_REMATCH[1]} == "#ifdef COMPAT_CANNOT_"* ]]; then
			ifs[level-1]=1
			((++silent))
			continue
		fi
	elif [[ $line =~ ^[[:space:]]*#else && ${ifs[level-1]} -ne 0 ]]; then
		((ifs[level-1]*=-1))
		((silent+=ifs[level-1]))
		continue
	elif [[ $line =~ ^[[:space:]]*#endif ]]; then
		((--level))
		[[ ${ifs[level]} -eq 1 ]] && ((--silent))
		[[ ${ifs[level]} -ne 0 ]] && continue
	fi
	[[ $silent -eq 0 ]] && printf '%s\n' "$line"
done < "$1" | clang-format -style="{ColumnLimit: 10000}"
