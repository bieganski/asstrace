#!/bin/bash

set -eux


sdb push Makefile /root/asstrace
sdb push asstrace.cc /root/asstrace
sdb push filter.cc /root/asstrace
sdb push api.h /root/asstrace
sdb push arch /root/asstrace/arch
sdb push gen/arm /root/asstrace/gen/arm
