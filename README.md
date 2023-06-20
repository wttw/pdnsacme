# pdnsacme
Create subzones for secure RFC 2136 updates for dns-01 letsencrypt validation

## Prove you own a hostname

Letsencrypt support using [dns-01](https://letsencrypt.org/docs/challenge-types/) proof of domain ownership. To do this your acme client
(e.g. [lego](https://github.com/go-acme/lego) has to be able to add and remove resource
records in the DNS zone.

If you're using PowerDNS you can do this via it's REST API, and I've been doing that for
years with dehydrated. But moving to use [RFC 2136](https://tools.wordtothewise.com/rfc2136)
makes some administration simpler.

PowerDNS supports [dynamic dns update](https://doc.powerdns.com/authoritative/dnsupdate.html)
but allowing dynamic dns updates for a zone is an all-or-nothing thing, you can't stop a client
from messing with anything in your zone. I'm not too concerned about someone compromising one
of my boxes and using the RFC 2136 shared secrets to cause havoc, but I'd like to lock it
down a little more.

So for each hostname I'm generating certificates for I'm creating a zone just for acme
authentication. www.example.com delegates to _acme-challenge.www.example.com and we only
allow dynamic DNS updates for that delegated zone.

That's deeply annoying to set up manually, though, and my DNS space isn't big enough to
need a full-on management system, so I put this hack together.

## Adding acme challenge zones on your DNS server

First, create a tsig key with `pdnsutil generate-tsig-key acme hmac-sha256`. You'll need it later;
you can see it with `pdnsutil list-tsig-keys`.

If you run `./pdnsacme www.example.com` it will read the powerdns configuration file to
get the API endpoint and key (if your user is a member of the pdns group you can do that,
just the same as pdnsutil does). Then for each hostname given on the commandline it will
check to see if there's already an acme challenge zone delegated. If there isn't, it will
create the challenge zone and delegate it from the longest matching zone.

That's almost everything that needs to be done, but the powerdns API library I'm using
doesn't seem to have any way to add zone metadata.

Shell to the rescue. `addacme.sh` takes a list of hostnames as parameters. For each one it
runs `pdnsacme` to add the challenge zone, then uses pdnsutil to add dynamic dns access to
for the challenge zone, only for the "acme" tsig key, and only from the IP address that the
hostname resolves to.

## On each server that needs certificates

I've included the lego wrapper script and hook I'm using. Install
[lego](https://github.com/go-acme/lego) and copy `renewcerts` and `certhook` to
`/usr/local/bin`. Edit `renewcerts` to have the list of hostnames you want in your
certificate, and the hostname and TSIG credentials of your DNS server.

Run `renewcerts run` once as root, to set up the lego state and get your initial
certificates. Then run `/usr/local/bin/renewcerts` daily from root's crontab.

## Bugs

It's a bit of a hack.

This isn't really production-ready, let alone perfect, but it let me set up rfc2136/dns-01
validated letsencrypt certs for my few dozen zones in a few minutes.
