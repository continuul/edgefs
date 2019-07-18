#!/bin/bash

PROTOC_REPO="protocolbuffers/protobuf"

# Credits to: lukechilds here: https://gist.github.com/lukechilds/a83e1d7127b78fef38c2914c4ececc3c
get_latest_release() {
  URL="https://api.github.com/repos/$1/releases/latest"
  VERSION=$(curl --silent $URL |grep '"tag_name":' |sed -E 's/.*"([^"]+)".*/\1/')
  echo $VERSION
}

LATEST_VERSION=$(get_latest_release ${PROTOC_REPO})
echo "Latest version is:  ${LATEST_VERSION}"
_VERSION=3.6.1

# grab the latest version
curl -OL https://github.com/${PROTOC_REPO}/releases/download/v${_VERSION}/protoc-${_VERSION}-linux-x86_64.zip

# Unzip
unzip protoc-${_VERSION}-linux-x86_64.zip -d protoc3

# Move protoc to /usr/local/bin/
mkdir -p ./bin
mv protoc3/bin/* ./bin/
rm -rf protoc3 protoc-*.zip

# Move protoc3/include to /usr/local/include/
#mv protoc3/include/* /usr/local/include/

exit 0
