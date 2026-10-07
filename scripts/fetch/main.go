// Generates local input files for sources the geoip converter can't read
// directly.
//
// Scans config.json for input entries carrying a custom arg that names a
// fetcher (e.g. {"type": "text", "args": {"uri": "./generated/<name>.txt",
// "arinOrg": ["ORG-HANDLE"]}}) and writes each entry's local uri file. The
// converter ignores the extra arg and just reads the generated file via its
// normal input plugin.
//
// Adding a source: write its fetch function and register it in fetchers.
//
// Run from the repo root: go run ./scripts/fetch
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A fetcher turns the value of its config.json arg into the contents of the
// entry's uri file, plus a one-line summary for the build log.
type fetcher struct {
	inputType string // converter input type that reads the generated file
	fetch     func(arg json.RawMessage) (data []byte, summary string, err error)
}

var fetchers = map[string]fetcher{
	"arinOrg":          {"text", fetchARIN},
	"azureServiceTags": {"json", fetchAzureServiceTags},
}

var client = &http.Client{Timeout: 60 * time.Second}

type statusError struct {
	url  string
	code int
}

func (e *statusError) Error() string {
	return fmt.Sprintf("%s: http status %d", e.url, e.code)
}

// get fetches url with the given request headers and fails on non-200 status
func get(url string, header map[string]string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &statusError{url, resp.StatusCode}
	}
	return io.ReadAll(resp.Body)
}

func main() {
	data, err := os.ReadFile("config.json")
	if err != nil {
		log.Fatalf("read config.json (run from the repo root): %v", err)
	}
	var cfg struct {
		Input []struct {
			Type string          `json:"type"`
			Args json.RawMessage `json:"args"`
		} `json:"input"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("parse config.json: %v", err)
	}

	found := false
	for _, in := range cfg.Input {
		if len(in.Args) == 0 {
			continue
		}
		var entry struct {
			Name string `json:"name"`
			URI  string `json:"uri"`
		}
		var args map[string]json.RawMessage
		if err := json.Unmarshal(in.Args, &entry); err != nil {
			log.Fatalf("parse config.json: %v", err)
		}
		if err := json.Unmarshal(in.Args, &args); err != nil {
			log.Fatalf("parse config.json: %v", err)
		}

		var field string
		var f fetcher
		for key := range args {
			if candidate, ok := fetchers[key]; ok {
				if field != "" {
					log.Fatalf("%s: only one of %s and %s can be set", entry.Name, field, key)
				}
				field, f = key, candidate
			}
		}
		if field == "" {
			continue
		}
		if in.Type != f.inputType || entry.URI == "" || strings.HasPrefix(strings.ToLower(entry.URI), "http") {
			log.Fatalf("%s: %s requires type %q and a local uri to generate", entry.Name, field, f.inputType)
		}
		found = true

		out, summary, err := f.fetch(args[field])
		if err != nil {
			log.Fatalf("%s: %v", entry.Name, err)
		}
		if err := os.MkdirAll(filepath.Dir(entry.URI), 0o755); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(entry.URI, out, 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %s -> %s\n", entry.Name, summary, entry.URI)
	}

	if !found {
		log.Println("no fetcher entries found in config.json")
	}
}
