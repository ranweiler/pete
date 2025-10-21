#!/usr/bin/env bash
set -eux -o pipefail

( cd nop; make )
( cd exec-off-leader; cargo build -r )
