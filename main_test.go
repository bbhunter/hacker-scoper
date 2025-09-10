package main

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"testing"
)

//========================================================================
//                            HELPER FUNCTIONS
//========================================================================

// ok fails the test if an err is not nil.
func checkForErrors(tb testing.TB, err error) {
	if err != nil {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d: unexpected error: %s\033[39m\n\n", filepath.Base(file), line, err.Error())
		tb.FailNow()
	}
}

// equals fails the test if exp is not equal to act.
func equals(tb testing.TB, exp, act interface{}) {
	if !reflect.DeepEqual(exp, act) {
		_, file, line, _ := runtime.Caller(1)
		fmt.Printf("\033[31m%s:%d:\n\n\texp: %#v\n\n\tgot: %#v\033[39m\n\n", filepath.Base(file), line, exp, act)
		tb.FailNow()
	}
}

//========================================================================
//========================================================================
//========================================================================

func Test_parseLine_Scope_IP(t *testing.T) {
	scope := "192.168.0.1"
	scopeParsed := net.ParseIP(scope)
	result, _ := parseLine(scope, true)
	equals(t, &scopeParsed, result)
}

func Test_parseLine_Scope_IPv4CIDR(t *testing.T) {
	scope := "192.168.0.1/24"
	_, scopeParsed, _ := net.ParseCIDR(scope)
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

func Test_parseLine_Scope_IPv6CIDR(t *testing.T) {
	scope := "2001:DB8::/32"
	_, scopeParsed, _ := net.ParseCIDR(scope)
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

func Test_parseLine_Scope_URL_Hostname(t *testing.T) {
	scope := "https://example.com"
	scopeParsed, _ := url.Parse(scope)
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

func Test_parseLine_Scope_URL_Hostname_NoScheme(t *testing.T) {
	scope := "example.com"
	scopeParsed, _ := url.Parse("https://" + scope)
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

func Test_parseLine_Scope_URL_Hostname_Port(t *testing.T) {
	scope := "http://example.com:80"
	scopeParsed, _ := url.Parse(scope)
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

func Test_parseLine_Scope_URL_Hostname_Port_NoScheme(t *testing.T) {
	scope := "example.com:80"
	scopeParsed, _ := url.Parse("https://" + scope)
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

func Test_parseLine_Scope_Invalid(t *testing.T) {
	scope := "Consequuntur et aut saepe quibusdam quia. Nostrum aut et et ea ea. Ducimus dolore aut unde. Unde a eligendi repudiandae tempore corrupti."
	result, err := parseLine(scope, true)
	equals(t, nil, result)
	equals(t, ErrInvalidFormat, err)
}

func Test_parseLine_Scope_URL_Scheme_Invalid(t *testing.T) {
	scope := "https://Consequuntur et aut saepe quibusdam quia. Nostrum aut et et ea ea. Ducimus dolore aut unde. Unde a eligendi repudiandae tempore corrupti."
	result, err := parseLine(scope, true)
	equals(t, nil, result)
	equals(t, ErrInvalidFormat, err)
}

// Scopes that are URLs with paths are expected to throw an error.
func Test_parseLine_Scope_URL_Hostname_WithPath(t *testing.T) {
	scope := "https://example.com/path/to/something.html"
	result, err := parseLine(scope, true)

	equals(t, nil, result)
	equals(t, ErrInvalidFormat, err)

}

// Scopes that are URLs with paths are expected to throw an error.
func Test_parseLine_Scope_URL_Hostname_Port_WithPath(t *testing.T) {
	scope := "https://example.com:80/path/to/something.html"
	result, err := parseLine(scope, true)

	equals(t, nil, result)
	equals(t, ErrInvalidFormat, err)

}

// Scopes that are URLs with paths are expected to throw an error.
func Test_parseLine_Scope_URL_Hostname_NoScheme_WithPath(t *testing.T) {
	scope := "example.com/path/to/something.html"
	result, err := parseLine(scope, true)

	equals(t, nil, result)
	equals(t, ErrInvalidFormat, err)

}

// Scopes that are URLs with paths are expected to throw an error.
func Test_parseLine_Scope_URL_Hostname_Port_NoScheme_WithPath(t *testing.T) {
	scope := "example.com:80/path/to/something.html"
	result, err := parseLine(scope, true)

	equals(t, nil, result)
	equals(t, ErrInvalidFormat, err)

}

// Scopes that are URLs with paths are expected to throw an error.
func Test_parseLine_Scope_URL_IP_WithPath(t *testing.T) {
	scope := "https://192.168.1.0/path/to/something.html"
	result, err := parseLine(scope, true)

	equals(t, nil, result)
	equals(t, ErrInvalidFormat, err)

}

// Scopes that are URLs with paths are expected to throw an error.
func Test_parseLine_Scope_URL_IP_NoScheme_WithPath(t *testing.T) {
	scope := "192.168.1.0/path/to/something.html"
	result, err := parseLine(scope, true)

	equals(t, nil, result)
	equals(t, ErrInvalidFormat, err)

}

// Scopes that are URLs with paths are expected to throw an error.
func Test_parseLine_Scope_URL_IP_Port_NoScheme_WithPath(t *testing.T) {
	scope := "192.168.1.0:80/path/to/something.html"
	result, err := parseLine(scope, true)

	equals(t, nil, result)
	equals(t, ErrInvalidFormat, err)

}

// Try parsing wildcards
func Test_parseLine_Scope_Wildcard_Start(t *testing.T) {
	scope := "*.amz.example.com"
	scopeParsed, _ := regexp.Compile(`.*\.amz\.example\.com`)
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

// Try parsing wildcards
func Test_parseLine_Scope_Wildcard_Middle(t *testing.T) {
	scope := "database*.internal.example.com"
	scopeParsed, _ := regexp.Compile(`database.*\.internal\.example\.com`)
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

// Try parsing wildcards
func Test_parseLine_Scope_Wildcard_Complex(t *testing.T) {
	scope := "database*.internal.*.example.com"
	scopeParsed, _ := regexp.Compile(`database.*\.internal\..*\.example\.com`)
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

func Test_parseLine_Target_IP(t *testing.T) {
	scope := "192.168.0.1"
	scopeParsed := net.ParseIP(scope)
	result, _ := parseLine(scope, true)
	equals(t, &scopeParsed, result)
}

func Test_parseLine_Target_IPv4CIDR(t *testing.T) {
	scope := "192.168.0.1/24"
	result, err := parseLine(scope, false)
	// If a CIDR range is given as a target (which doesn't make logical sense), the expected behavior is for it to be parsed as a URL with an IP host.
	// so "192.168.0.1/24" turns into "https://192.168.0.1/24" (where "/24" is the URL path)
	scopeAsIP := net.ParseIP("192.168.0.1")
	parsedScope := URLWithIPAddressHost{RawURL: scope, IPhost: scopeAsIP}

	checkForErrors(t, err)
	equals(t, &parsedScope, result)
}

// If a CIDR range is given as a target (which doesn't make logical sense), the expected behavior is for it to be parsed as a URL.
// so "2001:DB8::/32" turns into "https://2001:DB8::/32" (where "/32" is the URL path)
func Test_parseLine_Target_IPv6CIDR(t *testing.T) {
	scope := "2001:DB8::/32"
	parsedScope, _ := url.Parse("https://" + scope)
	result, err := parseLine(scope, false)

	checkForErrors(t, err)
	equals(t, parsedScope, result)
}

func Test_parseLine_Target_URL_Hostname(t *testing.T) {
	scope := "https://example.com"
	scopeParsed, _ := url.Parse(scope)
	result, _ := parseLine(scope, false)
	equals(t, scopeParsed, result)
}

func Test_parseLine_Target_URL_Hostname_NoScheme(t *testing.T) {
	scope := "example.com"
	scopeParsed, _ := url.Parse("https://" + scope)
	result, _ := parseLine(scope, false)
	equals(t, scopeParsed, result)
}

func Test_parseLine_Target_URL_Hostname_Port(t *testing.T) {
	scope := "http://example.com:80"
	scopeParsed, _ := url.Parse(scope)
	result, _ := parseLine(scope, false)
	equals(t, scopeParsed, result)
}

func Test_parseLine_Target_URL_Hostname_Port_NoScheme(t *testing.T) {
	scope := "example.com:80"
	scopeParsed, _ := url.Parse("https://" + scope)
	result, _ := parseLine(scope, false)
	equals(t, scopeParsed, result)
}

func Test_parseLine_Target_Invalid(t *testing.T) {
	scope := "Consequuntur et aut saepe quibusdam quia. Nostrum aut et et ea ea. Ducimus dolore aut unde. Unde a eligendi repudiandae tempore corrupti."
	result, err := parseLine(scope, false)
	equals(t, nil, result)
	equals(t, ErrInvalidFormat, err)
}

func Test_parseLine_Target_URL_Scheme_Invalid(t *testing.T) {
	scope := "https://Consequuntur et aut saepe quibusdam quia. Nostrum aut et et ea ea. Ducimus dolore aut unde. Unde a eligendi repudiandae tempore corrupti."
	result, err := parseLine(scope, false)
	equals(t, nil, result)
	equals(t, ErrInvalidFormat, err)
}

// Targets that are URLs with paths are expected to work
func Test_parseLine_Target_URL_Hostname_WithPath(t *testing.T) {
	scope := "https://example.com/path/to/something.html"
	parsedScope, _ := url.Parse(scope)
	result, err := parseLine(scope, false)

	equals(t, err, nil)
	equals(t, parsedScope, result)

}

// Targets that are URLs with paths are expected to work
func Test_parseLine_Target_URL_Hostname_Port_WithPath(t *testing.T) {
	scope := "https://example.com:80/path/to/something.html"
	parsedScope, _ := url.Parse(scope)
	result, err := parseLine(scope, false)

	equals(t, err, nil)
	equals(t, parsedScope, result)

}

// Targets that are URLs with paths are expected to work
func Test_parseLine_Target_URL_Hostname_NoScheme_WithPath(t *testing.T) {
	scope := "example.com/path/to/something.html"
	parsedScope, _ := url.Parse("https://" + scope)
	result, err := parseLine(scope, false)

	equals(t, err, nil)
	equals(t, parsedScope, result)

}

// Targets that are URLs with paths are expected to work
func Test_parseLine_Target_URL_Hostname_Port_NoScheme_WithPath(t *testing.T) {
	scope := "example.com:80/path/to/something.html"
	parsedScope, _ := url.Parse("https://" + scope)
	result, err := parseLine(scope, false)

	equals(t, err, nil)
	equals(t, parsedScope, result)

}

// Targets that are URLs with paths are expected to work
func Test_parseLine_Target_URL_IPv4_WithPath(t *testing.T) {
	scope := "https://192.168.1.0/path/to/something.html"
	scopeAsIP := net.ParseIP("192.168.1.0")
	parsedScope := URLWithIPAddressHost{RawURL: scope, IPhost: scopeAsIP}
	result, err := parseLine(scope, false)

	checkForErrors(t, err)
	equals(t, &parsedScope, result)

}

// Targets that are URLs with paths are expected to work
func Test_parseLine_Target_URL_IPv4_NoScheme_WithPath(t *testing.T) {
	scope := "192.168.1.0/path/to/something.html"
	scopeAsIP := net.ParseIP("192.168.1.0")
	parsedScope := URLWithIPAddressHost{RawURL: scope, IPhost: scopeAsIP}
	result, err := parseLine(scope, false)

	checkForErrors(t, err)
	equals(t, &parsedScope, result)

}

// Targets that are URLs with paths are expected to work
func Test_parseLine_Target_URL_IPv4_Port_NoScheme_WithPath(t *testing.T) {
	scope := "192.168.1.0:80/path/to/something.html"
	scopeAsIP := net.ParseIP("192.168.1.0")
	parsedScope := URLWithIPAddressHost{RawURL: scope, IPhost: scopeAsIP}
	result, err := parseLine(scope, false)

	checkForErrors(t, err)
	equals(t, &parsedScope, result)

}

/*
func Example_parseOutOfScopes() {
	// Test with an invalid out-of-scope string
	// In context, this function would print a warning to stderr and return false
	// However, for testing purposes, we will just check the stederr output
	assetURL, _ := url.Parse("https://example.com")
	outOfScopeString := "this is not even close to a URL"

	out := capturer.CaptureStderr(func() {
		_ = parseOutOfScopes(assetURL, outOfScopeString, nil)
	})

	fmt.Println(out)
	// Output: [33m[WARNING]: Couldn't parse out-of-scope "[38;2;0;204;255mhttps://[33mthis is not even close to a URL" as a URL.[0m
}
*/
/*
func Test_updateFireBountyJSON(t *testing.T) {
	// This test just verifies if the firebountyAPIURL is still available online, and if the JSON it returns still matches the expected structure.
	// firebountyAPIURL is a global variable defined in the main package.
	// First, we test if the URL is reachable with a HEAD request.
	fmt.Println(firebountyAPIURL)
	resp, err := http.Head("https://firebounty.com/api/v1/scope/all/url_only/")
	// if error is not nil and the response body has more than 1 byte, we fail the test.
	if err != nil || resp == nil || resp.ContentLength < 1 {
		t.Fatalf("Failed to reach firebounty API URL: %v", err)
	} else {
		// If the HEAD request is successful, we proceed to test the JSON structure.
		// We can use a simple HTTP GET request to fetch the JSON.
		resp, err = http.Get(firebountyAPIURL)
		checkForErrors(t, err)
		defer resp.Body.Close()

		// We can check if the Content-Type is application/json
		if resp.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("Expected Content-Type application/json, got %s", resp.Header.Get("Content-Type"))
		}

		// We can also check if the response body is not empty
		if resp.ContentLength == 0 {
			t.Fatal("Expected non-empty response body")
		}
	}
}
*/

func Test_removePortFromHost(t *testing.T) {
	// testURL must be in a variable of type *url.URL, which contains "https://example.com:8080/path?query=123"
	testURL, _ := url.Parse("https://example.com:8080/path?query=123")
	value := removePortFromHost(testURL)
	equals(t, "example.com", value)
}
