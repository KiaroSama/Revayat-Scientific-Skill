#!/bin/sh
set -eu
umask 077
test "$#" -eq 1
case "$1" in /input/*.tex) ;; *) exit 2 ;; esac
mkdir -p /tmp/tex-home /tmp/tex-var /tmp/tex-config
# Include aux files retain their relative directories in the isolated output.
find /input -mindepth 1 -type d -exec sh -c 'for directory do mkdir -p "/output/${directory#/input/}"; done' sh {} +
for pass in 1 2; do
    xelatex -no-shell-escape -interaction=nonstopmode -halt-on-error \
        -file-line-error -jobname=document -output-directory=/output "$1" > /output/console.log 2>&1
done
test -s /output/document.pdf
