// Generates plaintext CIDR lists from ARIN org registrations.
//
// Scans config.json for "text" input entries carrying a custom
// "arinOrg" field ({"uri": "./generated/<name>.txt", "arinOrg":
// ["ORG-HANDLE", ...]}) and writes each uri file with one CIDR per
// line. The geoip converter ignores the extra arinOrg field and just
// reads the generated file via its normal "text" input plugin.
//
// Covers netblocks that never show up in ASN-based sources — e.g. space
// owned by one company but announced via another's ASN (BYOIP on AWS).
//
// Run from the repo root: go run ./scripts/arin.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type netRef struct {
	Start string `json:"@startAddress"`
	End   string `json:"@endAddress"`
}

func fetchOrgRanges(handle string) ([]netRef, error) {
	url := fmt.Sprintf("https://whois.arin.net/rest/org/%s/nets", handle)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: http status %d", url, resp.StatusCode)
	}

	var payload struct {
		Nets struct {
			NetRef json.RawMessage `json:"netRef"`
		} `json:"nets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	// ARIN returns an array of nets, or a bare object when the org has one
	var refs []netRef
	if err := json.Unmarshal(payload.Nets.NetRef, &refs); err != nil {
		var single netRef
		if err := json.Unmarshal(payload.Nets.NetRef, &single); err != nil {
			return nil, fmt.Errorf("%s: unexpected netRef shape: %w", url, err)
		}
		refs = []netRef{single}
	}
	return refs, nil
}

// rangeToCIDRs splits an inclusive IP range into the minimal set of CIDRs
func rangeToCIDRs(startStr, endStr string) ([]netip.Prefix, error) {
	start, err := netip.ParseAddr(startStr)
	if err != nil {
		return nil, err
	}
	end, err := netip.ParseAddr(endStr)
	if err != nil {
		return nil, err
	}
	if start.Is4() != end.Is4() {
		return nil, fmt.Errorf("mixed address families in range %s - %s", startStr, endStr)
	}

	bits := start.BitLen()
	cur := new(big.Int).SetBytes(start.AsSlice())
	last := new(big.Int).SetBytes(end.AsSlice())
	if cur.Cmp(last) > 0 {
		return nil, fmt.Errorf("range start after end: %s - %s", startStr, endStr)
	}

	var prefixes []netip.Prefix
	one := big.NewInt(1)
	for cur.Cmp(last) <= 0 {
		// widest block aligned at cur...
		size := cur.TrailingZeroBits()
		if cur.Sign() == 0 || size > uint(bits) {
			size = uint(bits)
		}
		// ...that still fits within the remaining range
		remain := new(big.Int).Sub(last, cur)
		remain.Add(remain, one)
		if maxSize := uint(remain.BitLen() - 1); size > maxSize {
			size = maxSize
		}

		buf := make([]byte, bits/8)
		cur.FillBytes(buf)
		addr, ok := netip.AddrFromSlice(buf)
		if !ok {
			return nil, fmt.Errorf("invalid address bytes in range %s - %s", startStr, endStr)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, bits-int(size)))

		cur.Add(cur, new(big.Int).Lsh(one, size))
	}
	return prefixes, nil
}

func main() {
	data, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("read config.json (run from the repo root): %v", err)
	}
	var cfg struct {
		Input []struct {
			Type string `json:"type"`
			Args struct {
				Name    string   `json:"name"`
				URI     string   `json:"uri"`
				ArinOrg []string `json:"arinOrg"`
			} `json:"args"`
		} `json:"input"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("parse config.json: %v", err)
	}

	found := false
	for _, in := range cfg.Input {
		name, uri, handles := in.Args.Name, in.Args.URI, in.Args.ArinOrg
		if len(handles) == 0 {
			continue
		}
		if in.Type != "text" || uri == "" || strings.HasPrefix(strings.ToLower(uri), "http") {
			log.Fatalf("%s: arinOrg requires type \"text\" and a local uri to generate", name)
		}
		found = true

		seen := make(map[netip.Prefix]bool)
		for _, handle := range handles {
			refs, err := fetchOrgRanges(handle)
			if err != nil {
				log.Fatalf("%s: %v", name, err)
			}
			for _, ref := range refs {
				prefixes, err := rangeToCIDRs(ref.Start, ref.End)
				if err != nil {
					log.Fatalf("%s: %v", name, err)
				}
				for _, p := range prefixes {
					seen[p] = true
				}
			}
		}
		if len(seen) == 0 {
			log.Fatalf("ARIN returned no networks for %s (%s)", name, strings.Join(handles, ", "))
		}

		list := make([]netip.Prefix, 0, len(seen))
		for p := range seen {
			list = append(list, p)
		}
		sort.Slice(list, func(i, j int) bool {
			a, b := list[i], list[j]
			if a.Addr().Is4() != b.Addr().Is4() {
				return a.Addr().Is4()
			}
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c < 0
			}
			return a.Bits() < b.Bits()
		})

		lines := make([]string, len(list))
		for i, p := range list {
			lines[i] = p.String()
		}
		if err := os.MkdirAll(filepath.Dir(uri), 0o755); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(uri, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %d CIDRs from %s -> %s\n", name, len(lines), strings.Join(handles, ", "), uri)
	}

	if !found {
		log.Println("no arinOrg entries found in config.json")
	}
}
