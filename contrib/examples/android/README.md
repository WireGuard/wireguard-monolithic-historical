# Tools for Android

This currently contains a version of wg-quick.bash that works with
Android 7's `ndc` command. It requires the WireGuard module to be
part of your kernel, but after that, the usual `wg-quick up` and
`wg-quick down` commands work normally.

## Installation

Build a `wg` binary for Android and place it in this folder. Then
copy this folder some place on your phone, and run `sh ./install.sh`
as root. It should survive ROM flashes.

## Usage

Compared to the ordinary wg-quick, this one gains a "DNS =" field,
but loses SaveConfig and {Pre,Post}{Up,Down}.

Put your configuration files into `/data/misc/wireguard/`. After that,
the normal `wg-quick up|down` commands will work.

