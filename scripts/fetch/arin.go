// Plaintext CIDR lists from ARIN org registrations.
//
// "text" entries carry an "arinOrg" arg ({"uri": "./generated/<name>.txt",
// "arinOrg": ["ORG-HANDLE", ...]}) and get one CIDR per line.
//
// Covers netblocks that never show up in ASN-based sources — e.g. space
// owned by one company but announced via another's ASN (BYOIP on AWS).
package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net/netip"
	"sort"
	"strings"
)

type netRef struct {
	Start string `json:"@startAddress"`
	End   string `json:"@endAddress"`
}

func fetchOrgRanges(handle string) ([]netRef, error) {
	url := fmt.Sprintf("https://whois.arin.net/rest/org/%s/nets", handle)
	body, err := get(url, map[string]string{"Accept": "application/json"})
	if err != nil {
		return nil, err
	}

	var payload struct {
		Nets struct {
			NetRef json.RawMessage `json:"netRef"`
		} `json:"nets"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
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

func fetchARIN(arg json.RawMessage) ([]byte, string, error) {
	var handles []string
	if err := json.Unmarshal(arg, &handles); err != nil || len(handles) == 0 {
		return nil, "", fmt.Errorf("arinOrg must be a non-empty list of org handles")
	}

	seen := make(map[netip.Prefix]bool)
	for _, handle := range handles {
		refs, err := fetchOrgRanges(handle)
		if err != nil {
			return nil, "", err
		}
		for _, ref := range refs {
			prefixes, err := rangeToCIDRs(ref.Start, ref.End)
			if err != nil {
				return nil, "", err
			}
			for _, p := range prefixes {
				seen[p] = true
			}
		}
	}
	if len(seen) == 0 {
		return nil, "", fmt.Errorf("ARIN returned no networks for %s", strings.Join(handles, ", "))
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
	summary := fmt.Sprintf("%d CIDRs from %s", len(lines), strings.Join(handles, ", "))
	return []byte(strings.Join(lines, "\n") + "\n"), summary, nil
}
