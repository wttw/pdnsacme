package main

import (
	"bufio"
	"context"
	"fmt"
	"github.com/joeig/go-powerdns/v3"
	flag "github.com/spf13/pflag"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
)

type config struct {
	PDNSConfigFile string
	APIKey         string
	BaseURL        string
	Verbose        bool
}

func main() {
	c := config{}

	flag.BoolVarP(&c.Verbose, "verbose", "v", false, "Be verbose")
	flag.StringVar(&c.PDNSConfigFile, "pdns-config", "/etc/powerdns/pdns.conf", "Use this powerdns configuration")
	flag.Parse()

	err := c.load()
	if err != nil {
		log.Fatalln(err)
	}

	pdns := powerdns.NewClient(c.BaseURL, "", map[string]string{"X-API-Key": c.APIKey}, nil)
	ctx := context.Background()
	zones, err := pdns.Zones.List(ctx)
	if err != nil {
		log.Fatalf("failed to list zones: %v", err)
	}
	// Longest first
	sort.Slice(zones, func(i, j int) bool {
		return len(*zones[i].Name) > len(*zones[j].Name)
	})
	//for _, z := range zones {
	//	fmt.Printf("id: %s name: %s\n", *z.ID, *z.Name)
	//}
	for _, arg := range flag.Args() {
		err = handleZone(ctx, pdns, c, arg, zones)
		if err != nil {
			log.Fatalf("while handling %s: %s", arg, err)
		}
	}
}

func (c *config) load() error {
	in, err := os.Open(c.PDNSConfigFile)
	if err != nil {
		return err
	}

	re := regexp.MustCompile(`^(api-key|webserver-address|webserver-port)\s*=\s*(\S*)\s*$`)
	address := "127.0.0.1"
	port := "8081"

	scanner := bufio.NewScanner(in)
	for scanner.Scan() {
		matches := re.FindStringSubmatch(scanner.Text())
		if matches != nil {
			switch matches[1] {
			case "webserver-address":
				address = matches[2]
			case "webserver-port":
				port = matches[2]
			case "api-key":
				c.APIKey = matches[2]
			default:
				panic(fmt.Errorf("shouldn't happen: %s (%s)", matches[1], scanner.Text()))
			}
		}
	}
	c.BaseURL = fmt.Sprintf("http://%s:%s", address, port)
	if c.Verbose {
		log.Printf("Connecting via %s", c.BaseURL)
	}
	return nil
}

func handleZone(ctx context.Context, pdns *powerdns.Client, c config, zone string, zones []powerdns.Zone) error {
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}
	keyZone := "_acme-challenge." + zone

	var parentZone *powerdns.Zone

	for _, z := range zones {
		if *z.Name == keyZone {
			log.Printf("%s already has an authentication subzone, skipping", zone)
			return nil
		}
		if strings.HasSuffix(keyZone, *z.Name) {
			var err error
			parentZone, err = pdns.Zones.Get(ctx, *z.Name)
			if err != nil {
				return fmt.Errorf("failed to get zone %s: %s", *z.Name, err)
			}
			break
		}
	}

	if parentZone.Name == nil {
		return fmt.Errorf("No parent zone found for %s", keyZone)
	}

	fmt.Printf("Parent zone = %s\n", *parentZone.Name)
	//encoder := json.NewEncoder(os.Stdout)
	//encoder.SetEscapeHTML(false)
	//encoder.SetIndent("    ", "  ")
	//_ = encoder.Encode(parentZone)

	var soaRecord string
	var nsRecords []powerdns.Record
	var nameservers []string

	for _, rrset := range parentZone.RRsets {
		if *rrset.Name != *parentZone.Name {
			continue
		}
		if *rrset.Type == powerdns.RRTypeSOA {
			soaRecord = *rrset.Records[0].Content
		}
		if *rrset.Type == powerdns.RRTypeNS {
			for _, rr := range rrset.Records {
				nsRecords = append(nsRecords, rr)
				nameservers = append(nameservers, *rr.Content)
			}
		}
	}

	fmt.Printf("soa=%#v ns=%#v\n", soaRecord, nsRecords)

	newZone := &powerdns.Zone{
		Name: powerdns.String(keyZone),
		Kind: powerdns.ZoneKindPtr(powerdns.NativeZoneKind),
		RRsets: []powerdns.RRset{
			{
				Name: powerdns.String(keyZone),
				Type: powerdns.RRTypePtr(powerdns.RRTypeSOA),
				TTL:  powerdns.Uint32(600),
				Records: []powerdns.Record{{
					Content:  powerdns.String(soaRecord),
					Disabled: powerdns.Bool(false),
				}},
			},
			{
				Name:    powerdns.String(keyZone),
				Type:    powerdns.RRTypePtr(powerdns.RRTypeNS),
				TTL:     powerdns.Uint32(600),
				Records: nsRecords,
			},
		},
		DNSsec:      powerdns.Bool(*parentZone.DNSsec),
		APIRectify:  powerdns.Bool(true),
		Nameservers: nil,
	}

	if *parentZone.DNSsec {
		newZone.Nsec3Param = powerdns.String("")
		newZone.Nsec3Narrow = powerdns.Bool(false)
	}

	_, err := pdns.Zones.Add(ctx, newZone)
	if err != nil {
		return fmt.Errorf("failed to create zone %s: %w", keyZone, err)
	}

	err = pdns.Records.Add(ctx, *parentZone.Name, keyZone, powerdns.RRTypeNS, 600, nameservers)
	if err != nil {
		return fmt.Errorf("failed to add delegation for %s to %s: %w", keyZone, *parentZone.Name, err)
	}

	return nil
}
