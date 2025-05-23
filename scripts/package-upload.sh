#!/usr/bin/env bash

set -e
set -x

FILE="${1}"
PACKAGE="${2}"
VERSION="${3}"


echo "Package File: ${FILE}"
echo "Package: ${PACKAGE}"
echo "Version: ${VERSION}"
echo "Prerelease: ${IS_PRERELEASE}"

if [[ ${IS_PRERELEASE} == "true" ]]; then
  echo "Skipping artifact upload; IS_PRERELEASE is 'true'"
  exit 0;
fi

if [ "${FILE: -4}" == ".deb" ]; then
  if [[ "${FILE}" =~ "armhf6" ]]; then
    echo "Skipping ${FILE} due to GCP Artifact Registry armhf conflict!"
  else
    gcloud storage cp ${FILE} gs://artifacts-outgoing/${PACKAGE}/deb/${VERSION}/
  fi
else
  gcloud storage cp ${FILE} gs://artifacts-outgoing/${PACKAGE}/rpm/${VERSION}/
fi
