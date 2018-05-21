set_dns() {
	[[ ${#DNS[@]} -gt 0 ]] || return 0
	cmd systemd-resolve --interface="$INTERFACE" "${DNS[@]/#/--set-dns=}" --set-domain=~.
	HAVE_SET_DNS=1
}

unset_dns() {
	# We don't need to call --revert here, since the interface is being deleted
	# anyway, and systemd-resolved knows about that.
	return 0
}
