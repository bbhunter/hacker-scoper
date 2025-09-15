package main

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
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

// -----------------------------------
//     TESTING THE LINE PARSING

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
	myregex, _ := regexp.Compile(`.*\.amz\.example\.com`)
	scopeParsed := &WildcardScope{scope: *myregex}
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

// Try parsing wildcards
func Test_parseLine_Scope_Wildcard_Middle(t *testing.T) {
	scope := "database*.internal.example.com"
	myregex, _ := regexp.Compile(`database.*\.internal\.example\.com`)
	scopeParsed := &WildcardScope{scope: *myregex}
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

// Try parsing wildcards
func Test_parseLine_Scope_Wildcard_Complex(t *testing.T) {
	scope := "database*.internal.*.example.com"
	myregex, _ := regexp.Compile(`database.*\.internal\..*\.example\.com`)
	scopeParsed := &WildcardScope{scope: *myregex}
	result, _ := parseLine(scope, true)
	equals(t, scopeParsed, result)
}

// Try parsing regex
func Test_parseLine_Scope_Regex(t *testing.T) {
	scope := `^\w+:\/\/db[0-9][0-9][0-9]\.mycompany\.ec2\.amazonaws\.com.*$`
	scopeParsed, _ := regexp.Compile(scope)
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
	scopeAsIP := net.ParseIP("2001:DB8::")
	parsedScope := URLWithIPAddressHost{RawURL: scope, IPhost: scopeAsIP}
	result, err := parseLine(scope, false)

	checkForErrors(t, err)
	equals(t, &parsedScope, result)
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

// -----------------------------------
//     TESTING THE SCOPE MATCHING

func Test_isInscope_CIDR_IPv4(t *testing.T) {
	var result bool
	var scopes []interface{}
	assetIP := net.ParseIP("192.168.0.1")
	assetURLWithIPHost := URLWithIPAddressHost{RawURL: "https://192.168.0.1/path/to/stuff", IPhost: assetIP}
	assetURLPtr, _ := url.Parse("https://example.com/path/to/stuff")
	assetURL := *assetURLPtr
	var iface interface{}

	// Test inscope CIDR. --explicit-level=1
	_, cidr, _ := net.ParseCIDR("192.168.0.1/24")
	scopes = []interface{}{cidr}

	explicitLevel := 1

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)

	// Test out-of-scope CIDR. --explicit-level=1
	_, cidr, _ = net.ParseCIDR("192.168.1.1/24")
	scopes = []interface{}{cidr}

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)

	// Test inscope CIDR. --explicit-level=2
	// --explicit-level=2 shouldn't affect IP address scope matching.
	_, cidr, _ = net.ParseCIDR("192.168.0.1/24")
	scopes = []interface{}{cidr}

	explicitLevel = 2

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)

	// Test out-of-scope CIDR. --explicit-level=2
	_, cidr, _ = net.ParseCIDR("192.168.1.1/24")
	scopes = []interface{}{cidr}

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)

	// Test inscope CIDR. --explicit-level=3
	// --explicit-level=3 should disable CIDR range matching.
	_, cidr, _ = net.ParseCIDR("192.168.0.1/24")
	scopes = []interface{}{cidr}

	explicitLevel = 3

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)

	// Test out-of-scope CIDR. --explicit-level=3
	_, cidr, _ = net.ParseCIDR("192.168.1.1/24")
	scopes = []interface{}{cidr}

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
}

func Test_isInscope_CIDR_IPv6(t *testing.T) {
	var result bool
	var scopes []interface{}
	var iface interface{}
	assetIP := net.ParseIP("2001:DB8:0000:0000:0000:0000:0000:0001")
	assetURLWithIPHost := URLWithIPAddressHost{RawURL: "https://2001:DB8:0000:0000:0000:0000:0000:0001/path/to/stuff", IPhost: assetIP}
	assetURL, _ := url.Parse("https://example.com/path/to/stuff")

	// Test inscope CIDR. --explicit-level=1
	_, cidr, _ := net.ParseCIDR("2001:DB8::/32")
	scopes = []interface{}{cidr}

	explicitLevel := 1

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)

	// Test out-of-scope CIDR. --explicit-level=1
	_, cidr, _ = net.ParseCIDR("2001:DB9::/32")
	scopes = []interface{}{cidr}

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)

	// Test inscope CIDR. --explicit-level=2
	// --explicit-level=2 shouldn't affect IP address scope matching.
	_, cidr, _ = net.ParseCIDR("2001:DB8::/32")
	scopes = []interface{}{cidr}

	explicitLevel = 2

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)

	// Test out-of-scope CIDR. --explicit-level=2
	_, cidr, _ = net.ParseCIDR("2001:DB9::/32")
	scopes = []interface{}{cidr}

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)

	// Test inscope CIDR. --explicit-level=3
	// --explicit-level=3 should disable CIDR range matching.
	_, cidr, _ = net.ParseCIDR("2001:DB8::/32")
	scopes = []interface{}{cidr}

	explicitLevel = 3

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)

	// Test out-of-scope CIDR. --explicit-level=3
	_, cidr, _ = net.ParseCIDR("2001:DB9::/32")
	scopes = []interface{}{cidr}

	iface = &assetIP
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPHost
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
}

func Test_isInscope_URL(t *testing.T) {

	var result bool
	var scopes []interface{}
	var iface interface{}
	var explicitLevel int

	assetIPv6 := net.ParseIP("2001:DB8:0000:0000:0000:0000:0000:0001")
	assetURLWithIPv6Host := URLWithIPAddressHost{RawURL: "https://2001:DB8:0000:0000:0000:0000:0000:0001/path/to/stuff", IPhost: assetIPv6}
	assetIPv4 := net.ParseIP("192.168.0.1")
	assetURLWithIPv4Host := URLWithIPAddressHost{RawURL: "https://192.168.0.1/path/to/stuff", IPhost: assetIPv4}
	pointerToassetURL, _ := url.Parse("https://example.com/path/to/stuff")
	assetURL := *pointerToassetURL

	scope, _ := url.Parse("https://example.com")
	scopes = append(scopes, scope)
	explicitLevel = 1

	iface = &assetIPv4
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv4Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetIPv6
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv6Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result)

	pointerToassetURL, _ = url.Parse("https://unrelatedwebsite.com/path/to/stuff")
	assetURL = *pointerToassetURL
	// explicitLevel still equals 1

	iface = &assetIPv4
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv4Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetIPv6
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv6Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)

	pointerToassetURL, _ = url.Parse("https://somesubdomain.example.com/path/to/stuff")
	assetURL = *pointerToassetURL
	// explicitLevel still equals 1

	iface = &assetIPv4
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv4Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetIPv6
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv6Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result)

	pointerToassetURL, _ = url.Parse("https://example.com/path/to/stuff")
	assetURL = *pointerToassetURL
	explicitLevel = 2

	iface = &assetIPv4
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv4Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetIPv6
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv6Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result) // Since the scope is still just "https://example.com", this should succeed

	pointerToassetURL, _ = url.Parse("https://somesubdomain.example.com/path/to/stuff")
	assetURL = *pointerToassetURL
	// explicitLevel = 2

	iface = &assetIPv4
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv4Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetIPv6
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv6Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result) // Since the scope is still just "https://example.com", this should fail

	myregex := regexp.MustCompile(`.*\.example.com`)
	regexScope := &WildcardScope{scope: *myregex}
	scopes = []interface{}{regexScope}

	iface = &assetIPv4
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv4Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetIPv6
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv6Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result) // Since the scope now has a wildcard, this should succeed.

	explicitLevel = 3

	iface = &assetIPv4
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv4Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetIPv6
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv6Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result) // The scope has a wildcard, but in explicitlevel=3 wildcards are ignored. This should fail.

	scope, _ = url.Parse("https://somesubdomain.example.com")
	scopes = []interface{}{scope}

	iface = &assetIPv4
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv4Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetIPv6
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURLWithIPv6Host
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, false, result)
	iface = &assetURL
	result = isInscope(&scopes, &iface, &explicitLevel)
	equals(t, true, result) // The scope is now explicit. This should succeed.

	scopeRegex := regexp.MustCompile(`^\w+:\/\/db[0-9][0-9][0-9]\.mycompany\.ec2\.amazonaws\.com.*$`)
	scopes = []interface{}{scopeRegex}
	pointerToassetURL, _ = url.Parse("http://db123.mycompany.ec2.amazonaws.com/path/to/stuff")
	assetURL = *pointerToassetURL
	for explicitLevel = 1; explicitLevel < 3; explicitLevel++ {
		iface = &assetIPv4
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURLWithIPv4Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetIPv6
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURLWithIPv6Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURL
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, true, result) // The scope is now explicit. But regex scopes aren't disabled by --explicit-level=3. This should succeed.

	}

	pointerToassetURL, _ = url.Parse("http://db123.someothercompany.ec2.amazonaws.com/path/to/stuff")
	assetURL = *pointerToassetURL
	for explicitLevel = 1; explicitLevel < 3; explicitLevel++ {
		iface = &assetIPv4
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURLWithIPv4Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetIPv6
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURLWithIPv6Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURL
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result) // The scope is now explicit. This should fail.
	}

}

func Test_isInscope_IP(t *testing.T) {
	var result bool
	var scope net.IP
	var scopes []interface{}
	var iface interface{}
	var explicitLevel int

	assetIPv6 := net.ParseIP("2001:DB8:0000:0000:0000:0000:0000:0001")
	assetURLWithIPv6Host := URLWithIPAddressHost{RawURL: "https://2001:DB8:0000:0000:0000:0000:0000:0001/path/to/stuff", IPhost: assetIPv6}
	assetIPv4 := net.ParseIP("192.168.0.1")
	assetURLWithIPv4Host := URLWithIPAddressHost{RawURL: "https://192.168.0.1/path/to/stuff", IPhost: assetIPv4}
	pointerToassetURL, _ := url.Parse("https://example.com/path/to/stuff")
	assetURL := *pointerToassetURL

	for explicitLevel = 1; explicitLevel <= 3; explicitLevel++ {
		fmt.Println(strconv.Itoa(explicitLevel))
		scope = net.ParseIP("192.168.0.1")
		scopes = []interface{}{&scope}

		iface = &assetIPv4
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, true, result)
		iface = &assetURLWithIPv4Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, true, result)
		iface = &assetIPv6
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURLWithIPv6Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURL
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)

		scope = net.ParseIP("192.168.0.2")
		scopes = []interface{}{&scope}

		iface = &assetIPv4
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURLWithIPv4Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetIPv6
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURLWithIPv6Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURL
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)

		scope = net.ParseIP("2001:DB8:0000:0000:0000:0000:0000:0001")
		scopes = []interface{}{&scope}

		iface = &assetIPv4
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURLWithIPv4Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetIPv6
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, true, result)
		iface = &assetURLWithIPv6Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, true, result)
		iface = &assetURL
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)

		scope = net.ParseIP("2001:DB9:0000:0000:0000:0000:0000:0001")
		scopes = []interface{}{&scope}

		iface = &assetIPv4
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURLWithIPv4Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetIPv6
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURLWithIPv6Host
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
		iface = &assetURL
		result = isInscope(&scopes, &iface, &explicitLevel)
		equals(t, false, result)
	}

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
