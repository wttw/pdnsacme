#!/bin/bash

for zone in "$@"
do
    ip=`dig +short $zone`
    ./pdnsacme $zone
    pdnsutil set-meta "_acme-challenge.$zone" ALLOW-DNSUPDATE-FROM "$ip/32"
    pdnsutil set-meta "_acme-challenge.$zone" TSIG-ALLOW-DNSUPDATE acme
    pdnsutil get-meta "_acme-challenge.$zone"
done
