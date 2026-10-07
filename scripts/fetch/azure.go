// Azure IP ranges and service tags, as published by Microsoft.
//
// "json" entries carry an "azureServiceTags" arg with the Download Center id
// of the file ({"uri": "./generated/azure.json", "azureServiceTags":
// "56519"}) and get the file as downloaded, for jsonPath to pick from.
//
// Microsoft publishes a new file weekly and the publish date is part of its
// name, so the current link is scraped from the download's details page.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"time"
)

const azureDetailsURL = "https://www.microsoft.com/en-us/download/details.aspx?id=%s"

// The Download Center answers 403 to non-browser user agents
var browserHeader = map[string]string{
	"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
}

var serviceTagsLink = regexp.MustCompile(`https://download\.microsoft\.com/download/[^"'\s<>]+/ServiceTags_[A-Za-z]+_[0-9]{8}\.json`)

// Download paths that stay fixed between releases (only the date in the file
// name changes), probed when the details page can't be scraped.
var serviceTagsFallback = map[string]string{
	"56519": "https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_%s.json",
}

func fetchAzureServiceTags(arg json.RawMessage) ([]byte, string, error) {
	var id string
	if err := json.Unmarshal(arg, &id); err != nil || id == "" {
		return nil, "", fmt.Errorf("azureServiceTags must be a Download Center id string")
	}

	url, data, err := scrapeServiceTags(id)
	if err != nil {
		pattern, ok := serviceTagsFallback[id]
		if !ok {
			return nil, "", err
		}
		log.Printf("warning: %v; probing recent file names instead", err)
		if url, data, err = probeServiceTags(pattern); err != nil {
			return nil, "", err
		}
	}

	var tags struct {
		ChangeNumber int    `json:"changeNumber"`
		Cloud        string `json:"cloud"`
		Values       []struct {
			Properties struct {
				AddressPrefixes []string `json:"addressPrefixes"`
			} `json:"properties"`
		} `json:"values"`
	}
	if err := json.Unmarshal(data, &tags); err != nil {
		return nil, "", fmt.Errorf("%s: %w", url, err)
	}
	prefixes := 0
	for _, v := range tags.Values {
		prefixes += len(v.Properties.AddressPrefixes)
	}
	if prefixes == 0 {
		return nil, "", fmt.Errorf("%s: no address prefixes in the file", url)
	}

	summary := fmt.Sprintf("%d tags, %d prefixes (%s cloud, change %d) from %s",
		len(tags.Values), prefixes, tags.Cloud, tags.ChangeNumber, url)
	return data, summary, nil
}

// scrapeServiceTags downloads the file linked from the details page
func scrapeServiceTags(id string) (string, []byte, error) {
	page, err := get(fmt.Sprintf(azureDetailsURL, id), browserHeader)
	if err != nil {
		return "", nil, err
	}
	links := serviceTagsLink.FindAllString(string(page), -1)
	if len(links) == 0 {
		return "", nil, fmt.Errorf("no service tags link on the details page of download %s", id)
	}

	// Dated names sort chronologically, take the newest if several are listed
	sort.Strings(links)
	url := links[len(links)-1]
	data, err := get(url, browserHeader)
	return url, data, err
}

// probeServiceTags walks back from today to the newest dated file that
// exists. Releases are weekly, so three weeks covers a skipped one.
func probeServiceTags(pattern string) (string, []byte, error) {
	day := time.Now().UTC()
	for range 22 {
		url := fmt.Sprintf(pattern, day.Format("20060102"))
		data, err := get(url, browserHeader)
		var status *statusError
		if errors.As(err, &status) && status.code == http.StatusNotFound {
			day = day.AddDate(0, 0, -1)
			continue
		}
		return url, data, err
	}
	return "", nil, fmt.Errorf("no file matching %s in the last 22 days", pattern)
}
