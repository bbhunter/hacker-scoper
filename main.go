package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

const firebountyAPIURL = "https://firebounty.com/api/v1/scope/all/url_only/"
const firebountyJSONFilename = "firebounty-scope-url_only.json"

var firebountyJSONPath string

// https://tutorialedge.net/golang/parsing-json-with-golang/
type Scope struct {
	Scope      string //either a domain, or a wildcard domain
	Scope_type string //we only care about "web_application"
}

type Program struct {
	Firebounty_url string //url.URL not allowed appearently
	Scopes         struct {
		In_scopes     []Scope
		Out_of_scopes []Scope
	}
	Slug string
	Tag  string
	Url  string //url.URL not allowed appearently
	Name string
}

type WhiteLists struct {
	Regex        string //can't be "*regexp.Regexp" because they're actually domain wildcards
	Program_slug string
}

type Firebounty struct {
	White_listed []WhiteLists
	Pgms         []Program
}

type firebountySearchMatch struct {
	companyIndex int
	companyName  string
}

var chainMode bool
var targetsListFilepath string
var targetsListFile *os.File
var includeUnsure bool

const colorReset = "\033[0m"
const colorYellow = "\033[33m"
const colorRed = "\033[38;2;255;0;0m"
const colorGreen = "\033[38;2;37;255;36m"
const colorBlue = "\033[38;2;0;204;255m"

var usedstdin bool
var inscopeOutputFile string
var inscopeURLs []string
var unsureURLs []string
var outputDomainsOnly bool

func main() {

	var version string
	var showVersion bool
	var company string
	var explicitLevel int //should only be [0], 1, or 2
	var scopesListFilepath string
	var outofScopesListFilepath string
	usedstdin = false

	version = "v4.0.0"

	const usage = `Hacker-scoper is a Go (v1.17.2) tool designed to assist cybersecurity professionals in bug bounty programs. It identifies and excludes URLs and IP addresses that fall outside a program's scope by comparing input targets (URLs/IPs) against a locally cached [FireBounty](https://firebounty.com) database of scraped scope data. Users may also supply a custom scope list for validation.

` + colorBlue + `Usage:` + colorReset + ` hacker-scoper --file /path/to/targets [--company company | --custom-inscopes-file /path/to/inscopes [--custom-outofcopes-file /path/to/outofscopes]] [--explicit-level INT] [--reuse Y/N] [--chain-mode] [--database /path/to/firebounty.json] [--include-unsure] [--output /path/to/outputfile] [--hostnames-only]

` + colorBlue + `Usage examples:` + colorReset + `
  Example: Cat a file, and lookup scopes on firebounty
  ` + colorGreen + `cat recon-targets.txt | hacker-scoper -c google` + colorReset + `

  Example: Cat a file, and use the .inscope & .noscope files
  ` + colorGreen + `cat recon-targets.txt | hacker-scoper` + colorReset + `

  Example: Manually pick a file, lookup scopes on firebounty, and set explicit-level
  ` + colorGreen + `hacker-scoper -f recon-targets.txt -c google -e 2` + colorReset + `

  Example: Manually pick a file, use custom scopes and out-of-scope files, and set explicit-level
  ` + colorGreen + `hacker-scoper -f recon-targets.txt -ins inscope -oos noscope.txt -e 2 ` + colorReset + `

` + colorBlue + `Usage notes:` + colorReset + `
  If no company and no inscope file is specified, hacker-scoper will look for ".inscope" and ".noscope" files in the current or in parent directories.

` + colorBlue + `List of all possible arguments:` + colorReset + `
  -c, --company string
      Specify the company name to lookup.

  -f, --file string
      Path to your file containing URLs

  -ins, --inscope-file string
      Path to a custom plaintext file containing scopes

  -oos, --outofcope-file string
      Path to a custom plaintext file containing scopes exclusions

  -e, --explicit-level int
      How explicit we expect the scopes to be:
       1 (default): Include subdomains in the scope even if there's not a wildcard in the scope
       2: Include subdomains in the scope only if there's a wildcard in the scope
       3: Include subdomains in the scope only if they are explicitly within the scope 

  -ch, --chain-mode
      In "chain-mode" we only output the important information. No decorations.
	    Default: false
	
  --database string
      Custom path to the cached firebounty database.
	  	Default:
		- Windows: %APPDATA%\hacker-scoper\
		- Linux: /etc/hacker-scoper/
		- Android: $HOME/.hacker-scoper/

  -iu, --include-unsure
      Include "unsure" URLs in the output. An unsure URL is a URL that's not in scope, but is also not out of scope. Very probably unrelated to the bug bounty program.

  -o, --output string
      Save the inscope urls to a file

  -ho, --hostnames-only
      Output only hostnames instead of the full URLs

  --version
      Show the installed version

`

	flag.StringVar(&company, "c", "", "Specify the company name to lookup.")
	flag.StringVar(&company, "company", "", "Specify the company name to lookup.")
	flag.StringVar(&targetsListFilepath, "f", "", "Path to your file containing URLs")
	flag.StringVar(&targetsListFilepath, "file", "", "Path to your file containing URLs")
	flag.StringVar(&scopesListFilepath, "ins", "", "Path to a custom plaintext file containing scopes")
	flag.StringVar(&scopesListFilepath, "inscope-file", "", "Path to a custom plaintext file containing scopes")
	flag.StringVar(&outofScopesListFilepath, "oos", "", "Path to a custom plaintext file containing scopes exclusions")
	flag.StringVar(&outofScopesListFilepath, "outofcope-file", "", "Path to a custom plaintext file containing scopes exclusions")
	flag.IntVar(&explicitLevel, "e", 1, "Level of explicity expected. ([1]/2/3)")
	flag.IntVar(&explicitLevel, "explicit-level", 1, "Level of explicity expected. ([1]/2/3)")
	flag.BoolVar(&chainMode, "ch", false, "In \"chain-mode\" we only output the important information. No decorations.")
	flag.BoolVar(&chainMode, "chain-mode", false, "In \"chain-mode\" we only output the important information. No decorations.")
	flag.StringVar(&firebountyJSONPath, "database", "", "Custom path to the cached firebounty database")
	flag.StringVar(&inscopeOutputFile, "o", "", "Save the inscope urls to a file")
	flag.StringVar(&inscopeOutputFile, "output", "", "Save the inscope urls to a file")
	flag.BoolVar(&showVersion, "version", false, "Show installed version")
	flag.BoolVar(&includeUnsure, "iu", false, "Include \"unsure\" URLs in the output. An unsure URL is a URL that's not in scope, but is also not out of scope. Very probably unrelated to the bug bounty program.")
	flag.BoolVar(&includeUnsure, "include-unsure", false, "Include \"unsure\" URLs in the output. An unsure URL is a URL that's not in scope, but is also not out of scope. Very probably unrelated to the bug bounty program.")
	flag.BoolVar(&outputDomainsOnly, "ho", false, "Output only domains instead of the full URLs")
	flag.BoolVar(&outputDomainsOnly, "hostnames-only", false, "Output only domains instead of the full URLs")
	//https://www.antoniojgutierrez.com/posts/2021-05-14-short-and-long-options-in-go-flags-pkg/
	flag.Usage = func() { fmt.Print(usage) }
	flag.Parse()

	banner := `
'||                      '||                      '                                                 
 || ..    ....     ....   ||  ..    ....  ... ..     ....    ....    ...   ... ...    ....  ... ..  
 ||' ||  '' .||  .|   ''  || .'   .|...||  ||' ''   ||. '  .|   '' .|  '|.  ||'  || .|...||  ||' '' 
 ||  ||  .|' ||  ||       ||'|.   ||       ||       . '|.. ||      ||   ||  ||    | ||       ||     
.||. ||. '|..'|'  '|...' .||. ||.  '|...' .||.      |'..|'  '|...'  '|..|'  ||...'   '|...' .||.    
                                                                            ||                      
                                                                           ''''                     
`

	if showVersion {
		fmt.Print("hacker-scoper:" + version + "\n")
		os.Exit(0)
	}

	if firebountyJSONPath == "" {
		switch runtime.GOOS {
		case "android":
			//To maintain support between termux and other terminal emulators, we'll just save it in $HOME
			firebountyJSONPath = os.Getenv("HOME") + "/.hacker-scoper/"

		case "linux":
			firebountyJSONPath = "/etc/hacker-scoper/"

		case "windows":
			firebountyJSONPath = os.Getenv("APPDATA") + "\\hacker-scoper\\"

		default:
			if !chainMode {
				warning("This OS isn't officially supported. The firebounty JSON will be downloaded in the current working directory. To override this behaviour, use the \"--fire\" flag.")
			}

			firebountyJSONPath = ""
		}

		if firebountyJSONPath != "" {
			//If the folder exists...
			_, err := os.Stat(firebountyJSONPath)
			if errors.Is(err, os.ErrNotExist) {
				//Create the folder
				err := os.Mkdir(firebountyJSONPath, 0600)
				if err != nil {
					crash("Unable to create the folder \""+firebountyJSONPath+"\"", err)
				}
			} else if err != nil {
				// Schrodinger: file may or may not exist. See err for details.
				crash("Could not verify existance of the folder \""+firebountyJSONPath+"\"!", err)
			}
		}
	}

	firebountyJSONPath = firebountyJSONPath + firebountyJSONFilename

	if !chainMode {
		fmt.Println(banner)
	}

	//validate arguments
	if (explicitLevel != 1) && (explicitLevel != 2) && explicitLevel != 3 {
		var err error
		crash("Invalid explicit-level selected", err)
	}

	// If we're getting input from stdin...
	//https://stackoverflow.com/a/26567513/11490425
	stat, _ := os.Stdin.Stat()
	if (stat.Mode()&os.ModeCharDevice) == 0 && !isVSCodeDebug() {

		var stdinInput string

		//read stdin
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			stdinInput += "\n" + scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			crash("bufio couldn't read stdin correctly.", err)
		}

		// Write to disk in a securely-generated temporary file (CWE-377)
		//os.CreateTemp(dir, pattern string) (*File, error)
		secureTempFile, err := os.CreateTemp("", "hacker-scoper_stdin-scopes-tmp-file*.txt")
		if err != nil {
			crash("Couldn't create tmp file for storing stdin.", err)
		}
		err = os.WriteFile(secureTempFile.Name(), []byte(stdinInput), 0600)
		if err != nil {
			crash("Couldn't save write to tmp file.", err)
		}

		_, err = popLine(secureTempFile)
		if err != nil {
			crash("An unknown error ocurred while reading the temporary file for processing the stdin input.", err)
		}

		usedstdin = true

		targetsListFile = secureTempFile

	} else {
		// We didn't get anything from stdin, so we will use the file specified by the user
		// Immediatly open the file specified by the user to prevent the file from potentially being modified by another process, exploiting a race condition (CWE-377)

		//clean targetsListFilepath path for +speed
		targetsListFilepath = filepath.Clean(targetsListFilepath)

		//open the user-supplied URL list
		var err error
		targetsListFile, err = os.Open(targetsListFilepath) // #nosec G304 -- targetsListFilepath is a CLI argument specified by the user running the program. It is not unsafe to allow them to open any file in their own system.
		if err != nil {
			crash("Could not open your provided URL list file", err)
		}

	}

	if company == "" && scopesListFilepath == "" {
		//var err error
		//crash("A company name is required to smartly weed-out out-of-scope URLs", err)

		if !chainMode {
			fmt.Print("No company or scopes file specified. Looking for a \".inscope\" file..." + "\n")
		}

		//look for .inscope file
		inscopePath, err := searchForFileBackwards(".inscope")
		if err != nil {
			crash("Couldn't locate a .inscope file.", err)
		}

		if !chainMode {
			fmt.Print(".inscope found. Using " + inscopePath + "\n")
		}

		//look for .inscope file
		noscopePath, err := searchForFileBackwards(".noscope")
		if err != nil {
			noscopePath = ""
		} else if !chainMode {
			fmt.Print(".noscope found. Using " + noscopePath + "\n")
		}

		inscopeFileio, err := os.Open(inscopePath) // #nosec G304 -- inscopePath is a CLI argument specified by the user running the program. It is not unsafe to allow them to open any file in their own system.
		if err != nil {
			crash("Couldn't open "+inscopePath, err)
		}

		//Read the file line per line using bufio
		scopesScanner := bufio.NewScanner(inscopeFileio)

		for scopesScanner.Scan() {
			parseScopesWrapper(scopesScanner.Text(), explicitLevel, targetsListFile, noscopePath, nil)
		}
		err = inscopeFileio.Close()
		if err != nil {
			crash("Couldn't close '"+inscopePath+"'. The file was already closed.", err)
		}

		err = targetsListFile.Close()
		if err != nil {
			crash("Couldn't close '"+targetsListFilepath+"'. The file was already closed.", err)
		}

	} else {

		//user selected a company. Use the firebounty db
		if company != "" {
			if firebountyJSONFileStats, err := os.Stat(firebountyJSONPath); err == nil {
				// path/to/whatever exists
				//check age. if age > 24hs
				yesterday := time.Now().Add(-24 * time.Hour)
				if firebountyJSONFileStats.ModTime().Before(yesterday) {
					if !chainMode {
						fmt.Println("[INFO]: +24hs have passed since the last update to the local firebounty database. Updating...")
					}
					updateFireBountyJSON()
				}

			} else if errors.Is(err, os.ErrNotExist) {
				//path/to/whatever does not exist
				if !chainMode {
					fmt.Println("[INFO]: Downloading scopes file and saving in \"" + firebountyJSONPath + "\"")
				}

				updateFireBountyJSON()

			} else {
				// Schrodinger: file may or may not exist. See err for details.
				panic(err)
			}

			//open json
			jsonFile, err := os.Open(firebountyJSONPath) // #nosec G304 -- firebountyJSONPath is a CLI argument specified by the user running the program. It is not unsafe to allow them to open any file in their own system.
			if err != nil {
				crash("Couldn't open firebounty JSON. Maybe run \"chmod 777 "+firebountyJSONPath+"\"? ", err)
			}

			//read the json file as bytes
			byteValue, _ := io.ReadAll(jsonFile)
			jsonFile.Close() // #nosec G104 -- No need to worry about double-closing issues, as the file is closed right after reading it.

			var firebountyJSON Firebounty
			err = json.Unmarshal(byteValue, &firebountyJSON)
			if err != nil {
				crash("Couldn't parse firebountyJSON into pre-defined struct.", err)
			}

			var matchingCompanyList []firebountySearchMatch
			var userChoice string
			var userPickedInvalidChoice bool = true
			var userChoiceAsInt int

			//for every company...
			for companyCounter := 0; companyCounter < len(firebountyJSON.Pgms); companyCounter++ {
				fcompany := strings.ToLower(firebountyJSON.Pgms[companyCounter].Name)
				if strings.Contains(fcompany, company) {
					matchingCompanyList = append(matchingCompanyList, firebountySearchMatch{companyCounter, firebountyJSON.Pgms[companyCounter].Name})
				}
			}
			if len(matchingCompanyList) == 0 && !chainMode {
				fmt.Println(string(colorRed) + "[-] 0 (lowercase'd) company names contained the string \"" + company + "\"" + string(colorReset))
				fmt.Println(string(colorRed) + "[-] Consider either of these options:")
				fmt.Println(string(colorRed) + "\t - Doing a manual search at https://firebounty.com")
				fmt.Println(string(colorRed) + "\t - Loading the scopes manually into '.inscope' and '.noscope' files.")
				fmt.Println(string(colorRed) + "\t - Loading the scopes manually into custom files, specified with the --inscope-file and --outofscope-file arguments.")
			} else if len(matchingCompanyList) > 1 {

				if chainMode {
					err = nil
					crash("Unable to match the company to a single company. Please use a more exact company string.", err)
				}

				//appearently "while" doesn't exist in Go. It has been replaced by "for"
				for userPickedInvalidChoice {
					//For every matchingCompanyList item...
					for i := 0; i < len(matchingCompanyList)-1; i++ {
						//Print it
						fmt.Println("    " + strconv.Itoa(i) + " - " + matchingCompanyList[i].companyName)
					}

					//Show user the option to combine all of the previous companies as if they were a single company
					fmt.Println("    " + strconv.Itoa(len(matchingCompanyList)) + " - COMBINE ALL")

					//Get userchoice
					fmt.Print("\n[+] Multiple companies matched \"" + company + "\". Please choose one: ")
					_, err = fmt.Scanln(&userChoice)
					if err != nil {
						crash("An error ocurred while reading user input.", err)
					}

					//Convert userchoice str -> int
					userChoiceAsInt, err = strconv.Atoi(userChoice)
					//If the user picked something invalid...
					if err != nil {
						warning("Invalid option selected!")
					} else {
						userPickedInvalidChoice = false
					}
				}

				//tip
				fmt.Println("[-] If you want to remove one of these options, feel free to modify your firebounty database: " + firebountyJSONPath + "\n")

				//If the user chose to "COMBINE ALL"...
				if userChoiceAsInt == len(matchingCompanyList) {
					//for every company that matched the company query...
					for i := 0; i < len(matchingCompanyList); i++ {

						//Load the matchingCompanyList 2D slice, and convert the first member from string to integer, and save the company index
						companyIndex := matchingCompanyList[i].companyIndex
						parseCompany(company, firebountyJSON, companyIndex, explicitLevel, outofScopesListFilepath)
					}
				} else {

					//Use userChoiceAsInt as an index for the matchingCompanyList 2D slice, and save the company index
					companyCounter := matchingCompanyList[userChoiceAsInt].companyIndex
					parseCompany(company, firebountyJSON, companyCounter, explicitLevel, outofScopesListFilepath)
				}

			} else {
				//Only 1 company matched the query
				parseCompany(company, firebountyJSON, matchingCompanyList[0].companyIndex, explicitLevel, outofScopesListFilepath)
			}

			//user chose to use their own scope list
		} else {

			if _, err := os.Stat(scopesListFilepath); err == nil {
				// path/to/whatever exists

				//when using this custom scope, most likely there will be more targets than scopes, so we will nest scopes->targets for more efficiency

				//open the file
				//https://stackoverflow.com/a/16615559/11490425
				scopesFile, err := os.Open(scopesListFilepath) // #nosec G304 -- scopesListFilepath is a CLI argument specified by the user running the program. It is not unsafe to allow them to open any file in their own system.
				if err != nil {
					crash("Could not open "+scopesListFilepath, err)
				}

				//Read the file line per line using bufio
				scopesScanner := bufio.NewScanner(scopesFile)

				for scopesScanner.Scan() {
					parseScopesWrapper(scopesScanner.Text(), explicitLevel, targetsListFile, outofScopesListFilepath, nil)
				}
				err = scopesFile.Close()
				if err != nil {
					crash("Couldn't close '"+scopesListFilepath+"'. The file was already closed.", err)
				}
				err = targetsListFile.Close()
				if err != nil {
					crash("Couldn't close '"+scopesListFilepath+"'. The file was already closed.", err)
				}

			} else if errors.Is(err, os.ErrNotExist) {
				//path/to/whatever does not exist
				err = nil
				crash(scopesListFilepath+" does not exist.", err)

			} else {
				// Schrodinger: file may or may not exist. See err for details.
				panic(err)
			}
		}

	}

	inscopeURLs = removeDuplicateStr(inscopeURLs)
	sort.Strings(inscopeURLs)

	if includeUnsure {
		unsureURLs = removeDuplicateStr(unsureURLs)
		sort.Strings(unsureURLs)

		//If a URL is in inscopeURLs and unsureURLs, remove it from unsureURLs
	unsureURLsloopstart:
		for i := 0; i < len(unsureURLs); i++ {
			for j := 0; j < len(inscopeURLs); j++ {
				if unsureURLs[i] == inscopeURLs[j] {
					unsureURLs = append(unsureURLs[:i], unsureURLs[i+1:]...)
					goto unsureURLsloopstart
				}
			}
		}

	}

	//Yes, I could've made this into a function instead of copying the same chunk of code, but it just doesn't make any sense as a function IMO
	//For each item in inscopeURLs...
	for i := 0; i < len(inscopeURLs); i++ {
		if !chainMode {
			infoGood("IN-SCOPE: ", inscopeURLs[i])
		} else {
			fmt.Println(inscopeURLs[i])
		}
	}

	if includeUnsure {
		//for each unsureURLs item...
		for i := 0; i < len(unsureURLs); i++ {
			if !chainMode {
				infoWarning("UNSURE: ", unsureURLs[i])
			} else {
				fmt.Println(unsureURLs[i])
			}
		}
	}

	//Add the URLs into the output file, if the flag has been set
	if inscopeOutputFile != "" {

		f, err := os.OpenFile(inscopeOutputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600) // #nosec G304 -- inscopeOutputFile is a CLI argument specified by the user running the program. It is not unsafe to allow them to open any file in their own system.
		if err != nil {
			crash("Unable to read output file", err)
		}

		//for each inscopeURLs item...
		for i := 0; i < len(inscopeURLs); i++ {
			//write it to the output file
			_, err = f.WriteString(inscopeURLs[i] + "\n")
			if err != nil {
				crash("Unable to write to output file", err)
			}
		}

		//Process unsure URLs
		if includeUnsure && unsureURLs != nil {
			//for each unsureURLs item...
			for i := 0; i < len(unsureURLs); i++ {
				//write it to the output file
				_, err = f.WriteString(unsureURLs[i] + "\n")
				if err != nil {
					crash("Unable to write to output file", err)
				}
			}
		}

		//Close the output file
		f.Close() // #nosec G104 -- There's no harm done if we're unable to close the output file, since we're already at the end of the program.
	}
	cleanup()

}

// https://stackoverflow.com/a/30948278/11490425
func popLine(f *os.File) ([]byte, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(make([]byte, 0, fi.Size()))

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(buf, f)
	if err != nil {
		return nil, err
	}

	line, err := buf.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, err
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}
	nw, err := io.Copy(f, buf)
	if err != nil {
		return nil, err
	}
	err = f.Truncate(nw)
	if err != nil {
		return nil, err
	}
	err = f.Sync()
	if err != nil {
		return nil, err
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		return nil, err
	}
	return line, nil
}

func updateFireBountyJSON() {
	// path/to/whatever does *not* exist
	//get the big JSON from the API
	jason, err := http.Get(firebountyAPIURL)
	if err != nil {
		crash("Could not download scopes from firebounty at: "+firebountyAPIURL, err)
	}

	//read the contents of the request
	body, err := io.ReadAll(jason.Body)
	jason.Body.Close() // #nosec G104 -- There is no situation in which closing the body of the request will cause an error.
	if err != nil {
		fmt.Println(err)
	}

	//delete the previous file (if it even exists)
	os.Remove(firebountyJSONPath) // #nosec G104 -- There is no need to handle any errors in deleting the file, as it will be created again in the next step.

	//write to disk
	err = os.WriteFile(firebountyJSONPath, []byte(string(body)), 0600)
	if err != nil {
		crash("Couldn't save firebounty json to disk as"+firebountyJSONPath, err)
	}

	if !chainMode {
		fmt.Println("[INFO]: Scopes file saved to " + firebountyJSONPath)
	}

}

// we may recieve one like the following as scope:
// example.com
// *.example.com
// 192.168.0.1
// 192.168.0.1/24
// 192.168.0.1
// 192.168.0.1/24
func parseScopes(scope string, isWilcard bool, targetsListFile *os.File, outofScopesListFilepath string, firebountyOutOfScopes []Scope, parseScopeAsRegex bool) {
	schemedScope := "http://" + scope

	var CIDR *net.IPNet
	var parseAsIP bool
	var scopeURL *url.URL
	var err error
	var scopeIP net.IP

	if !parseScopeAsRegex {
		//attempt to parse current scope as a CIDR range
		_, CIDR, _ = net.ParseCIDR(scope)
		scopeIP := net.ParseIP(scope)
		//if we can parse the scope as a CIDR range or as an IP address:
		if scopeIP.String() != "<nil>" || CIDR != nil {
			parseAsIP = true
		} else {
			parseAsIP = false
			scopeURL, err = url.Parse(schemedScope)
			if err != nil {
				if !chainMode {
					warning("Couldn't parse the scope " + scope + " as a valid URL.")
				}
				return
			}
		}
	} else {
		scope = strings.Replace(scope, ".", "\\.", -1)
		scope = strings.Replace(scope, "*", ".*", -1)
	}

	//Read the URLs file line per line
	//scan using bufio
	scanner := bufio.NewScanner(targetsListFile)

	for scanner.Scan() {
		//attempt to parse current target as an IP
		var currentTargetURL *url.URL
		currentTargetURL, err = url.Parse(scanner.Text())

		//If we couldn't parse it as is, attempt to add the "https://" prefix
		if err != nil || currentTargetURL.Host == "" {
			currentTargetURL, err = url.Parse("https://" + scanner.Text())
		}

		portlessHostofCurrentTarget := removePortFromHost(currentTargetURL)
		targetIp := net.ParseIP(portlessHostofCurrentTarget)

		//if it fails...
		if (err != nil || currentTargetURL.Host == "") && !chainMode {
			if usedstdin {
				warning("STDIN: Couldn't parse " + scanner.Text() + " as a valid URL.")
			} else {
				warning(targetsListFilepath + ": Couldn't parse " + scanner.Text() + " as a valid URL.")
			}

		} else {
			//if we have to parse this scope as a regex, and the current target is not an IP address...
			if parseScopeAsRegex && !(targetIp.String() != "" && parseAsIP) {

				//attempt to parse the scope as a regex
				scopeRegex, err := regexp.Compile(scope)
				if err != nil {
					crash("There was an error parsing the scope \""+scope+"\" as a regex. This scope was parsed as a regex instead of as a URL because it has 2 or more wildcards.", err)
				}

				//if the current target host matches the regex...
				if scopeRegex.MatchString(removePortFromHost(currentTargetURL)) {
					if !isOutOfScope(currentTargetURL, outofScopesListFilepath, nil, firebountyOutOfScopes) {
						if outputDomainsOnly {
							logInScope(currentTargetURL.Hostname())
						} else {
							logInScope(scanner.Text())
						}

					}
				} else if includeUnsure {
					if !isOutOfScope(currentTargetURL, outofScopesListFilepath, nil, firebountyOutOfScopes) {
						if outputDomainsOnly {
							logUnsure(currentTargetURL.Hostname())
						} else {
							logUnsure(scanner.Text())
						}
					}
				}

				//we were able to parse the target as a URL
				//if we were able to parse the target as an IP, and the scope as an IP or CIDR range
			} else if targetIp.String() != "" && parseAsIP {
				if parseScopeAsRegex {
					return
				}
				//if the CIDR range is empty
				if CIDR == nil {
					//Couldn't parse scope as CIDR range, retrying as ip match")
					if targetIp.String() == scopeIP.String() {
						if !isOutOfScope(nil, outofScopesListFilepath, targetIp, firebountyOutOfScopes) {
							if outputDomainsOnly {
								logInScope(targetIp.String())
							} else {
								logInScope(scanner.Text())
							}
						}

					} else if includeUnsure {
						if !isOutOfScope(nil, outofScopesListFilepath, targetIp, firebountyOutOfScopes) {
							if outputDomainsOnly {
								logUnsure(targetIp.String())
							} else {
								logUnsure(scanner.Text())
							}
						}
					}
				} else {
					if CIDR.Contains(targetIp) {
						if !isOutOfScope(nil, outofScopesListFilepath, targetIp, firebountyOutOfScopes) {
							if outputDomainsOnly {
								logInScope(targetIp.String())
							} else {
								logInScope(scanner.Text())
							}
						}
					} else if includeUnsure && targetIp.String() != "<nil>" {
						if !isOutOfScope(nil, outofScopesListFilepath, targetIp, firebountyOutOfScopes) {
							if outputDomainsOnly {
								logUnsure(targetIp.String())
							} else {
								logUnsure(scanner.Text())
							}
						}
					}
				}

			} else {
				//parse the scope & target as URLs

				if isWilcard {
					//parse the scope as a URL

					//if x is a subdomain of y
					//ex: wordpress.example.com with a scope of *.example.com will give a match
					//we DON'T do it by splitting on dots and matching, because that would cause errors with domains that have two top-level-domains (gov.br for example)
					if strings.HasSuffix(removePortFromHost(currentTargetURL), scopeURL.Host) {
						if !isOutOfScope(currentTargetURL, outofScopesListFilepath, nil, firebountyOutOfScopes) {
							if outputDomainsOnly {
								logInScope(currentTargetURL.Hostname())
							} else {
								logInScope(scanner.Text())
							}
						}

					} else if includeUnsure {
						if !isOutOfScope(currentTargetURL, outofScopesListFilepath, nil, firebountyOutOfScopes) {
							if outputDomainsOnly {
								logUnsure(currentTargetURL.Hostname())
							} else {
								logUnsure(scanner.Text())
							}
						}
					}
				} else {
					if removePortFromHost(currentTargetURL) == scopeURL.Host {
						if !isOutOfScope(currentTargetURL, outofScopesListFilepath, nil, firebountyOutOfScopes) {
							if outputDomainsOnly {
								logInScope(currentTargetURL.Hostname())
							} else {
								logInScope(scanner.Text())
							}
						}

					} else if includeUnsure {
						if !isOutOfScope(currentTargetURL, outofScopesListFilepath, nil, firebountyOutOfScopes) {
							if outputDomainsOnly {
								logUnsure(currentTargetURL.Hostname())
							} else {
								logUnsure(scanner.Text())
							}
						}
					}
				}

			}
		}

	}

	if err := scanner.Err(); err != nil {
		crash("Could not read URL List file successfully", err)
	}
}

func parseScopesWrapper(scope string, explicitLevel int, targetsListFile *os.File, outofScopesListFilepath string, firebountyOutOfScopes []Scope) {

	//if we have a wildcard domain
	if strings.HasPrefix(scope, "*.") {
		//shorter way of saying if explicitLevel == 2 || explicitLevel ==1
		if explicitLevel != 3 && strings.Count(scope, "*") == 1 {
			//remove wildcard ("*.")
			scope = strings.ReplaceAll(scope, "*.", "")
			parseScopes(scope, true, targetsListFile, outofScopesListFilepath, firebountyOutOfScopes, false)
		}

		//if the scope is in a weird wildcard format, containing more than one wildcard...
	} else if strings.Contains(scope, "*") {
		parseScopes(scope, true, targetsListFile, outofScopesListFilepath, firebountyOutOfScopes, true)
	} else if explicitLevel == 1 {
		//this is NOT a wildcard domain, but we'll treat it as such anyway
		parseScopes(scope, true, targetsListFile, outofScopesListFilepath, firebountyOutOfScopes, false)
	} else {
		//this is NOT a wildcard domain. we will parse it explicitly
		parseScopes(scope, false, targetsListFile, outofScopesListFilepath, firebountyOutOfScopes, false)
	}
}

func crash(message string, err error) {
	cleanup()
	fmt.Fprintf(os.Stderr, string(colorRed)+"[ERROR]: "+message+string(colorReset)+"\n\n")
	fmt.Fprintf(os.Stderr, string(colorRed)+"Error stacktrace: "+string(colorReset)+"\n")
	panic(err)
}

func warning(message string) {
	fmt.Fprintf(os.Stderr, string(colorYellow)+"[WARNING]: "+message+string(colorReset)+"\n")
}

func infoGood(prefix string, message string) {
	fmt.Print(string(colorGreen) + "[+] " + prefix + string(colorReset) + message + "\n")
}

func infoWarning(prefix string, message string) {
	fmt.Print(string(colorYellow) + "[+] " + prefix + string(colorReset) + message + "\n")
}

func removePortFromHost(url *url.URL) string {
	//code readability > efficiency
	portless := strings.Replace(string(url.Host), string(url.Port()), "", 1)
	//obligatory cleanup ("192.168.1.1:" -> "192.168.1.1")
	portless = strings.Replace(portless, ":", "", 1)
	return portless
}

// out-of-scopes are parsed as --explicit-level==2
func isOutOfScope(targetURL *url.URL, outofScopesListFilepath string, targetIP net.IP, firebountyOutOfScopes []Scope) bool {
	var err error

	if outofScopesListFilepath != "" {
		//user chose to use their own out-of-scopes file, or we detected a .noscope file
		if _, err = os.Stat(outofScopesListFilepath); err == nil {
			// path/to/whatever exists
			//open the file
			//https://stackoverflow.com/a/16615559/11490425
			outOfScopesFile, err := os.Open(outofScopesListFilepath) // #nosec G304 -- outofScopesListFilepath is a CLI argument specified by the user running the program. It is not unsafe to allow them to open any file in their own system.
			if err != nil {
				crash("Could not open "+outofScopesListFilepath, err)
			}

			//Read the file line per line using bufio
			outofScopeScanner := bufio.NewScanner(outOfScopesFile)

			for outofScopeScanner.Scan() {

				if parseOutOfScopes(targetURL, outofScopeScanner.Text(), targetIP) {
					return true
				}
			}
			err = outOfScopesFile.Close()
			if err != nil {
				crash("Couldn't close "+outofScopesListFilepath+" because it was already closed.", err)
			}
			return false

		} else if errors.Is(err, os.ErrNotExist) {
			// path/to/whatever does *not* exist
			crash("OutOfScopes file supplied, but it does not exist!", err)

		} else {
			// Schrodinger: file may or may not exist. See err for details.
			crash("Couldn't verify existance of outofscopesFile", err)

		}
	} else {
		//check target agains firebounty out-of-scopes
		//for every outOfScope
		for outOfScopeCounter := 0; outOfScopeCounter < len(firebountyOutOfScopes); outOfScopeCounter++ {
			//if the scope_type is web_application and it's not empty
			if firebountyOutOfScopes[outOfScopeCounter].Scope_type == "web_application" && firebountyOutOfScopes[outOfScopeCounter].Scope != "" {
				outOfScope := firebountyOutOfScopes[outOfScopeCounter].Scope
				if !chainMode {
					//alert the user about potentially mis-configured bug-bounty program
					if outOfScope[0:4] == "com." || outOfScope[0:4] == "org." {
						warning("Scope starting with \"com.\" or \"org. found. This may be a sign of a misconfigured bug bounty program. Consider editing the \"" + firebountyJSONPath + " file and removing the faulty entries. Also, report the failure to the maintainers of the bug bounty program.")
					}
				}
				if parseOutOfScopes(targetURL, outOfScope, targetIP) {
					return true
				}
			}

		}
	}

	//if we got no matches for any outOfScope
	return false
}

// Returns true if the targetURL is out of scope, false otherwise
// Only targetURL or targetIP should be non-nil
// If both are specified, targetURL will be used
// If both are nil, the function will return false
func parseOutOfScopes(targetURL *url.URL, outOfScope string, targetIP net.IP) bool {

	if targetURL != nil {
		//parse target as a URL

		//if the outofscope starts with a wildcard...
		if strings.HasPrefix(outOfScope, "*.") && strings.Count(outOfScope, "*") == 1 {
			outOfScopeURL, err := url.Parse("https://" + outOfScope)
			if err != nil {
				if !chainMode {
					warning("Couldn't parse out-of-scope \"" + outOfScope + "\" as a URL.")
				}
				return false
			}

			//if x is a subdomain of y
			//ex: wordpress.example.com with a scope of *.example.com will give a match
			//we DON'T do it by splitting on dots and matching, because that would cause errors with domains that have two top-level-domains (gov.br for example)
			if strings.HasSuffix(removePortFromHost(targetURL), outOfScopeURL.Host) {
				return true

			}

			//if the outofscope has more than one wildcard...
		} else if strings.Contains(outOfScope, "*") {

			//parse as regex
			outOfScope = strings.Replace(outOfScope, ".", "\\.", -1)
			outOfScope = strings.Replace(outOfScope, "*", ".*", -1)

			outOfScopeRegex, err := regexp.Compile(outOfScope)
			if err != nil {
				crash("There was an error parsing the noscope \""+outOfScope+"\" as a regex. This scope was parsed as a regex instead of as a URL because it has 2 or more wildcards.", err)
			}

			if outOfScopeRegex.MatchString(removePortFromHost(targetURL)) {
				return true
			}
		} else {
			// The scope has no wildcards

			var outOfScopeURL *url.URL
			var err error

			schemeRegex, _ := regexp.Compile(`^\w+:`)
			//if the outofscope starts with a scheme...
			if schemeRegex.MatchString(outOfScope) {
				// Parse it as it is
				outOfScopeURL, err = url.Parse(outOfScope)
				if err != nil {
					if !chainMode {
						warning("Couldn't parse out-of-scope \"" + outOfScope + "\" as a URL.")
					}
					return false
				}
			} else {
				// Add a scheme to it so it can be parsed as a URL
				outOfScopeURL, err = url.Parse("https://" + outOfScope)
				if err != nil {
					if !chainMode {
						warning("Couldn't parse out-of-scope \"" + colorBlue + "https://" + colorYellow + outOfScope + "\" as a URL.")
					}
					return false
				}
			}

			if removePortFromHost(targetURL) == outOfScopeURL.Host {
				return true

			}
		}
	} else {
		//IP mode
		//attempt to parse current outOfScope as an IP
		outOfScopeIp := net.ParseIP(outOfScope)
		//if we can parse the current outOfScope as an IP...
		if outOfScopeIp != nil {
			//try IP match
			if targetIP.String() == outOfScopeIp.String() {
				return true
			}
		}
	}

	//if nothing matched
	return false
}

//======================================================================================
// The following code is from tomnomnom's inscope project:
// https://github.com/tomnomnom/hacks/tree/master/inscope

func searchForFileBackwards(filename string) (string, error) {
	pwd, err := filepath.Abs(".")
	if err != nil {
		return "", err
	}

	for {
		_, err := os.Stat(filepath.Join(pwd, filename))

		// found one!
		if err == nil {
			return filepath.Join(pwd, filename), nil
		}

		newPwd := filepath.Dir(pwd)
		if newPwd == pwd {
			break
		}
		pwd = newPwd
	}

	return "", errors.New("unable to locate a \".scope\" file")
}

//======================================================================================

func cleanup() {
	if usedstdin {
		//Developers using temporary files are expected to clean up after themselves.
		//https://superuser.com/a/296827
		_ = targetsListFile.Close()
		err := os.Remove(targetsListFile.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, string(colorRed)+"[ERROR]: Unable to delete the temporary file at '"+targetsListFile.Name()+"'. Access permissions to this system's temp folder might have changed since the program started running. Make sure to delete the file manually to avoid clutter in your temp directory."+string(colorReset)+"\n")
			panic(err)
		}
	}
}

func logInScope(url string) {
	inscopeURLs = append(inscopeURLs, url)
}

func logUnsure(url string) {
	unsureURLs = append(inscopeURLs, url)
}

// Receives a slice of strings and returns a new slice with duplicates removed
func removeDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	list := []string{}
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func parseCompany(company string, firebountyJSON Firebounty, companyCounter int, explicitLevel int, outofScopesListFilepath string) {
	//match found!
	if !chainMode {
		fmt.Print("[+] Search for \"" + company + "\" matched the company " + string(colorGreen) + firebountyJSON.Pgms[companyCounter].Name + string(colorReset) + "!\n")

		// Print the details of the matched company in a readable format

		// Get the last date the cached database was updated
		info, err := os.Stat(firebountyJSONPath)
		if err != nil {
			crash("Error getting file information for the database file at "+firebountyJSONFilename, err)
		}
		// info.Atime_ns now contains the last access time
		// (in nanoseconds since the unix epoch)
		// Convert the date to the format YYYY-MM-DD HH:MM
		lastUpdated := time.Unix(info.ModTime().Unix(), 0).Format("2006-01-02 15:04:05")
		fmt.Println("[+] Last updated: " + lastUpdated)

		// Print the details of the matched company in a readable format
		fmt.Println("[+] Firebounty URL: " + firebountyJSON.Pgms[companyCounter].Firebounty_url)
		fmt.Println("[+] Program URL: " + firebountyJSON.Pgms[companyCounter].Url)

		// Print the in-scope rules
		fmt.Println("[+] In-scope rules: ")
		for _, inscope := range firebountyJSON.Pgms[companyCounter].Scopes.In_scopes {
			fmt.Println("\t[+] " + inscope.Scope_type + ": " + inscope.Scope)
		}

		// Print the out-of-scope rules
		fmt.Println("\n[+] Out-of-scope rules: ")
		for _, noscope := range firebountyJSON.Pgms[companyCounter].Scopes.Out_of_scopes {
			fmt.Println("\t[+] " + noscope.Scope_type + ": " + noscope.Scope)
		}

		fmt.Println("\n[+] Analysis started...")

	}
	//for every scope in the program
	for scopeCounter := 0; scopeCounter < len(firebountyJSON.Pgms[companyCounter].Scopes.In_scopes); scopeCounter++ {
		//if the scope type is "web_application" and it's not empty
		if firebountyJSON.Pgms[companyCounter].Scopes.In_scopes[scopeCounter].Scope_type == "web_application" && firebountyJSON.Pgms[companyCounter].Scopes.In_scopes[scopeCounter].Scope != "" {

			scope := firebountyJSON.Pgms[companyCounter].Scopes.In_scopes[scopeCounter].Scope

			if !chainMode {
				//attempt to parse current target as an IP
				var currentTargetURL *url.URL
				currentTargetURL, err := url.Parse(scope)

				//If we couldn't parse it as is, attempt to add the "https://" prefix
				if err != nil || currentTargetURL.Host == "" {
					currentTargetURL, _ = url.Parse("https://" + scope)
				}

				portlessHostofCurrentTarget := removePortFromHost(currentTargetURL)

				//alert the user about potentially mis-configured bug-bounty program
				_, scopeHasValidTLD := publicsuffix.PublicSuffix(portlessHostofCurrentTarget)

				if !scopeHasValidTLD && currentTargetURL.Host != "" {
					warning("\"" + scope + "\". Does not have a public Top Level Domain (TLD). This may be a sign of a misconfigured bug bounty program. Consider editing the \"" + firebountyJSONPath + " file and removing the faulty entries. Also, report the failure to the mainters of the bug bounty program.")
				}
			}

			parseScopesWrapper(scope, explicitLevel, targetsListFile, outofScopesListFilepath, firebountyJSON.Pgms[companyCounter].Scopes.Out_of_scopes)

		}
	}
}

func isVSCodeDebug() bool {
	// Set an environment variable in your VS Code launch config, e.g. "VSCODE_DEBUG=true"
	return os.Getenv("VSCODE_DEBUG") == "true"
}
