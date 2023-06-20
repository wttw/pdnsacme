#!/bin/bash

GOOS=linux GOARCH=386 go build && scp pdnsacme ns1.prod:.
