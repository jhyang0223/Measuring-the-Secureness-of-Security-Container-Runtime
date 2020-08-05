#!/bin/bash
(
  set -e
  URL=https://storage.googleapis.com/gvisor/releases/nightly/2019-11-04
  wget ${URL}/runsc
  wget ${URL}/runsc.sha512
  sha512sum -c runsc.sha512
  rm -f runsc.sha512
  sudo mv runsc /usr/local/bin
  sudo chown root:root /usr/local/bin/runsc
  sudo chmod 0755 /usr/local/bin/runsc
)

