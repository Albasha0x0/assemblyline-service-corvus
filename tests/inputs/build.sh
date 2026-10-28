#!/bin/sh
# Builds the files tests/documents were recorded from into the folder given (default tests/inputs/build).
# Requires gcc, upx, go, dpkg-deb, cpio, wixl (msitools), python3 and the .NET 10 SDK.
set -e
here=$(cd "$(dirname "$0")" && pwd)
out=$(mkdir -p "${1:-$here/build}" && cd "${1:-$here/build}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/deb/DEBIAN" "$work/deb/usr/share/hello"
cp "$here/notes.txt" "$work/deb/usr/share/hello/"
printf 'Package: hello\nVersion: 1.0.0\nArchitecture: all\nMaintainer: Example <dev@example.com>\nDescription: Notes file\n' \
    > "$work/deb/DEBIAN/control"
dpkg-deb --build --root-owner-group "$work/deb" "$out/hello.deb" > /dev/null

dotnet build -c Release -v q -o "$work/settings" "$here/settings/Settings.csproj" > /dev/null
cp "$work/settings/Settings.dll" "$out/"

cp "$here/mapped.js" "$out/"

gcc -O2 -o "$out/hello" "$here/hello.c"
# UPX does not pack this small position-independent build.
gcc -O2 -static -no-pie -o "$out/hello-packed" "$here/hello.c"
upx -q -q "$out/hello-packed" > /dev/null

(cd "$here/go" && go build -o "$out/hello-go" .)

dotnet build -c Release -v q -o "$work/marker" "$here/marker/Marker.csproj" > /dev/null
cp "$work/marker/Marker.dll" "$out/"

mkdir -p "$work/tree/usr/share/hello"
cp "$here/notes.txt" "$work/tree/usr/share/hello/"
(cd "$work/tree" && find . | cpio -o -H newc --quiet) > "$out/hello.cpio"

(cd "$here" && wixl -o "$out/hello.msi" hello.wxs)

python3 -I "$here/archives.py" "$out"
