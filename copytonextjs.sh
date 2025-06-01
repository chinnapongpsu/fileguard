#!/bin/sh
set -e
# This script copies the contents of the current directory to the nextjs directory
# and then copies the contents of the pkg directory to the web-nextjs/src/rust directory.

# Ensure the web-nextjs/src/rust directory exists
mkdir -p ./web-nextjs/src/rust;
# Copy the contents of the current directory to the web-nextjs/src/rust directory
echo "Copying pkg to web-nextjs/src/rust...";
cp -r ./pkg/* ./web-nextjs/src/rust/;

echo "Copying pkg to web-nextjs/src/rust completed.";