package main

import (
	"crypto/tls"
	"encoding/csv"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
)

var (
	// Define the security headers to check
	requiredHeaders = []string{
		"Content-Security-Policy",
		"Strict-Transport-Security",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}

	// Colors for output
	missingColor = color.New(color.FgRed).SprintFunc()
	presentColor = color.New(color.FgGreen).SprintFunc()

	// HTTP client
	client *http.Client
)

// fetchHeaders fetches the headers for a given URL
func fetchHeaders(url string) (http.Header, error) {
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "http://" + url
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return resp.Header, nil
}

// checkHeaders checks which headers are present or missing
func checkHeaders(headers http.Header) map[string]bool {
	results := make(map[string]bool)
	for _, header := range requiredHeaders {
		_, present := headers[header]
		results[header] = present
	}
	return results
}

// displayResults prints the results with color coding
func displayResults(url string, results map[string]bool) {
	fmt.Printf("\nResults for %s:\n", url)
	for header, present := range results {
		if present {
			fmt.Printf("  %s: %s\n", header, presentColor("Present"))
		} else {
			fmt.Printf("  %s: %s\n", header, missingColor("Missing"))
		}
	}
}

// writeResultsToCSV writes the results to a CSV file
func writeResultsToCSV(filePath string, results map[string]map[string]bool) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header row
	header := append([]string{"URL"}, requiredHeaders...)
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write data rows
	for url, headers := range results {
		row := []string{url}
		for _, header := range requiredHeaders {
			if headers[header] {
				row = append(row, "Present")
			} else {
				row = append(row, "Missing")
			}
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}

// readURLsFromFile reads a list of URLs from a file
func readURLsFromFile(filePath string) ([]string, error) {
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var urls []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			urls = append(urls, trimmed)
		}
	}
	return urls, nil
}

func main() {
	// Parse command-line flags
	missingOnly := flag.Bool("missing", false, "Display only missing headers with URLs")
	skipSSL := flag.Bool("skip-ssl", false, "Skip SSL verification")
	outputFile := flag.String("output", "", "Export results to a CSV file")
	inputFile := flag.String("input", "", "File containing a list of URLs")
	flag.Parse()

	// Get URLs from command-line arguments
	urls := flag.Args()

	// Read URLs from input file if specified
	if *inputFile != "" {
		fileURLs, err := readURLsFromFile(*inputFile)
		if err != nil {
			log.Fatalf("Error reading URLs from file: %v\n", err)
		}
		urls = append(urls, fileURLs...)
	}

	if len(urls) == 0 {
		fmt.Println("Usage: go run main.go [--missing] [--skip-ssl] [--input=<file>] [--output=<file.csv>] <URL1> <URL2> ...")
		os.Exit(1)
	}

	// Configure HTTP client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: *skipSSL},
	}
	client = &http.Client{Transport: tr}

	// Collect results for CSV export
	resultsForCSV := make(map[string]map[string]bool)

	// Process each URL
	for _, url := range urls {
		headers, err := fetchHeaders(url)
		if err != nil {
			log.Printf("Error fetching headers for %s: %v\n", url, err)
			continue
		}

		results := checkHeaders(headers)
		resultsForCSV[url] = results

		if *missingOnly {
			var missingHeaders []string
			for header, present := range results {
				if !present {
					missingHeaders = append(missingHeaders, header)
				}
			}
			if len(missingHeaders) > 0 {
				fmt.Printf("%s is missing: %s\n", url, strings.Join(missingHeaders, ", "))
			}
		} else {
			displayResults(url, results)
		}
	}

	// Export to CSV if specified
	if *outputFile != "" {
		err := writeResultsToCSV(*outputFile, resultsForCSV)
		if err != nil {
			log.Fatalf("Error writing to CSV: %v\n", err)
		}
		fmt.Printf("\nResults exported to %s\n", *outputFile)
	}
}

