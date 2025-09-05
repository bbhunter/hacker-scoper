package main

import (
	"bufio"
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
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

const firebountyAPIURL = "https://firebounty.com/api/v1/scope/all/url_only/"
const firebountyJSONFilename = "firebounty-scope-url_only.json"

var firebountyJSONPath string

var ErrInvalidFormat = errors.New("invalid format: not IP, CIDR, or URL")

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
var outputDomainsOnly bool

func main() {

	var version string
	var showVersion bool
	var company string
	// TODO: Replace the flag library with something that allows us to read and store explicit level straight into a uint8 variable. This doesn't need to be a full 32-bit int.
	// TODO: Add a separate --explicit-level flag for noscope. So we can have inscopeExplicitLevel, and noscope ExplicitLevel. Customization ftw!
	var explicitLevel int //should only be [0], 1, or 2
	var scopesListFilepath string
	var outofScopesListFilepath string
	usedstdin = false

	version = "v4.0.0"

	const usage = `Hacker-scoper is a Go (v1.17.2) tool designed to assist cybersecurity professionals in bug bounty programs. It identifies and excludes URLs and IP addresses that fall outside a program's scope by comparing input targets (URLs/IPs) against a locally cached [FireBounty](https://firebounty.com) database of scraped scope data. Users may also supply a custom scope list for validation.

` + colorBlue + `Usage:` + colorReset + ` hacker-scoper --file /path/to/targets [--company company | --custom-inscopes-file /path/to/inscopes [--custom-outofcopes-file /path/to/outofscopes]] [--explicit-level INT] [--chain-mode] [--database /path/to/firebounty.json] [--include-unsure] [--output /path/to/outputfile] [--hostnames-only]

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
		// TODO: Optimize this code so we don't check for the OS type on every single run. This should be handled by the compiler before-hand. This'll also make the program smaller since we won't need the "runtime" library anymore.
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
				warning("This OS isn't officially supported. The firebounty JSON will be downloaded in the current working directory. To override this behaviour, use the \"--database\" flag.")
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

	// Validate the targets input
	var targetsInput []string

	// If we're getting input from stdin...
	//https://stackoverflow.com/a/26567513/11490425
	stat, _ := os.Stdin.Stat()
	if (stat.Mode()&os.ModeCharDevice) == 0 && !isVSCodeDebug() {

		// Read all of stdin into targetsInput

		var targetsInput string

		//read stdin
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			targetsInput += "\n" + scanner.Text()
		}
		if err := scanner.Err(); err != nil {
			crash("bufio couldn't read stdin correctly.", err)
		}

		// Enable this for logging purposes
		usedstdin = true

	} else if targetsListFilepath != "" {
		// We didn't get anything from stdin, so we will use the file specified by the user
		// Immediatly open the file specified by the user to prevent the file from potentially being modified by another process, exploiting a race condition (CWE-377)

		// Load the user-supplied targets file into memory
		var err error
		targetsInput, err = readFileLines(targetsListFilepath)
		if err != nil {
			crash("Could not read the file "+targetsListFilepath, err)
		}

	} else {
		// We didn't get anything from stdin, and the user didn't specify a file
		// Print a usage warning, then quit gracefully

		if !chainMode {
			fmt.Println(string(colorRed) + "[-] No input file specified. Please specify a file with the -f or --file argument." + string(colorReset))
			fmt.Println(string(colorRed) + "[-] Run with \"--help\" for more information." + string(colorReset))
		}
		cleanup()

		// Exit code 2 = command line syntax error
		os.Exit(2)
	}

	var inscopeLines []string
	var noscopeLines []string

	// Validate the inscope input
	if company == "" && scopesListFilepath == "" {
		// If the user didn't specify a company name, and also didn't specify a filepath for the inscope and outofscope files, we'll search for .inscope and .noscope files.

		if !chainMode {
			fmt.Print("No company or scopes file specified. Looking for \".inscope\" and \".noscope\" files..." + "\n")
		}

		//look for .inscope file
		inscopePath, err := searchForFileBackwards(".inscope")
		if err != nil {
			crash("Couldn't locate a .inscope file.", err)
		}

		if !chainMode {
			fmt.Print(".inscope found. Using " + inscopePath + "\n")
		}

		//look for .noscope file
		noscopePath, err := searchForFileBackwards(".noscope")
		if err != nil {
			noscopePath = ""
		} else if !chainMode {
			fmt.Print(".noscope found. Using " + noscopePath + "\n")
		}

		// Load the inscope file into memory
		inscopeLines, err = readFileLines(inscopePath)
		if err != nil {
			crash(".inscope file found at "+inscopePath+" but couldn't be read.", err)
		}

		// Load the noscope file into memory
		noscopeLines, err = readFileLines(noscopePath)
		if err != nil {
			crash(".noscope file found at "+noscopePath+" but couldn't be read.", err)
		}

	} else if company != "" {
		// If the user inputted a company name, we'll lookup said company in the firebounty db

		// If the db exists...
		if firebountyJSONFileStats, err := os.Stat(firebountyJSONPath); err == nil {
			//check age. if age > 24hs
			yesterday := time.Now().Add(-24 * time.Hour)
			if firebountyJSONFileStats.ModTime().Before(yesterday) {
				if !chainMode {
					fmt.Println("[INFO]: +24hs have passed since the last update to the local firebounty database. Updating...")
				}
				updateFireBountyJSON()
			}
		} else if errors.Is(err, os.ErrNotExist) {
			// The database does not exist.
			// We'll create it.
			if !chainMode {
				fmt.Println("[INFO]: Downloading scopes file and saving in \"" + firebountyJSONPath + "\"")
			}
			updateFireBountyJSON()
		} else {
			crash("Unable to get information about the database file at \""+firebountyJSONPath+"\". Probably a permissions error with the directory the database is saved at. Try using the database argument like '--database /custom/path/to/store/the/firebounty.json'", err)
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
		// TODO: Optimize this by using Partial JSON Processing
		// https://dev.to/aaravjoshi/boosting-golang-json-performance-10-proven-techniques-for-high-speed-processing-4f9m#partial-json-processing
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
			cleanup()
			// Exit code 2 = command line syntax error
			os.Exit(2)
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
					tempinscopeLines, tempnoscopeLines, err := getCompanyScopes(&firebountyJSON, &companyIndex)
					if err != nil {
						crash("Error parsing the company "+company, err)
					}

					inscopeLines = append(inscopeLines, tempinscopeLines...)
					noscopeLines = append(noscopeLines, tempnoscopeLines...)

				}
			} else {
				// The user chose a specific company
				// Use userChoiceAsInt as an index for the matchingCompanyList 2D slice, and save the company index
				companyCounter := matchingCompanyList[userChoiceAsInt].companyIndex
				inscopeLines, noscopeLines, err = getCompanyScopes(&firebountyJSON, &companyCounter)
				if err != nil {
					crash("Error parsing the company "+company, err)
				}
			}

		} else {
			//Only 1 company matched the query
			fmt.Print("[+] Search for \"" + company + "\" matched the company " + string(colorGreen) + firebountyJSON.Pgms[matchingCompanyList[0].companyIndex].Name + string(colorReset) + "!\n")
			inscopeLines, noscopeLines, err = getCompanyScopes(&firebountyJSON, &matchingCompanyList[0].companyIndex)
			if err != nil {
				crash("Error parsing the company "+company, err)
			}
		}

	} else {
		//user chose to use their own scope list
		if _, err := os.Stat(scopesListFilepath); err == nil {
			// path/to/whatever exists

			// Load the user-supplied inscopes file into memory
			inscopeLines, err = readFileLines(scopesListFilepath)
			if err != nil {
				crash("Error reading the file "+scopesListFilepath, err)
			}

			// The outofScopesListFilepath might, or might not have been specified.
			// If a custom outofScopesListFilepath was specified...
			if outofScopesListFilepath != "" {
				// Load the user-supplied noscopes file into memory
				noscopeLines, err = readFileLines(outofScopesListFilepath)
				if err != nil {
					crash("Error reading the file "+outofScopesListFilepath, err)
				}
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

	// Parse all inscopeLines lines
	inscopeScopes, err := parseAllLines(inscopeLines, true)
	if err != nil {
		crash("Unable to parse any inscope entries as scopes", err)
	}

	// Parse all noscopeLines lines
	noscopeScopes, err := parseAllLines(noscopeLines, true)
	if err != nil {
		crash("Unable to parse any noscope entries as scopes", err)
	}

	// Parse all targetsInput lines
	targets, err := parseAllLines(targetsInput, false)
	if err != nil {
		crash("Unable to parse any target entries as valid assets.", err)
	}

	inscopeAssets, unsureAssets := parseAllScopes(&inscopeScopes, &noscopeScopes, &targets, &explicitLevel)
	//OLD DEF: func parseScopesWrapper(scope string, explicitLevel int, targetsListFile *os.File, outofScopesListFilepath string, firebountyOutOfScopes []Scope
	//NEW DEF: func parseScopesWrapper(inscopeScopes *[]interface{}, explicitLevel *int, targetsInput *[]string, noscopeScopes *[]interface{}) ([]string, []string, error) {

	/*
		if includeUnsure {
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
	*/

	inscopeAssetsAsStrings := interfaceToStrings(&inscopeAssets, false)
	unsureAssetsAsStrings := interfaceToStrings(&unsureAssets, false)

	//Yes, I could've made this into a function instead of copying the same chunk of code, but it just doesn't make any sense as a function IMO
	//For each item in inscopeAssetsAsStrings...
	for i := range inscopeAssetsAsStrings {
		if !chainMode {
			infoGood("IN-SCOPE: ", inscopeAssetsAsStrings[i])
		} else {
			fmt.Println(inscopeAssetsAsStrings[i])
		}
	}

	if includeUnsure {
		//for each unsureURLs item...
		for i := 0; i < len(unsureAssetsAsStrings); i++ {
			if !chainMode {
				infoWarning("UNSURE: ", unsureAssetsAsStrings[i])
			} else {
				fmt.Println(unsureAssetsAsStrings[i])
			}
		}
	}

	//Add the URLs into the output file, if the flag has been set
	if inscopeOutputFile != "" {

		f, err := os.OpenFile(inscopeOutputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600) // #nosec G304 -- inscopeOutputFile is a CLI argument specified by the user running the program. It is not unsafe to allow them to open any file in their own system.
		if err != nil {
			crash("Unable to read output file", err)
		}

		//for each inscope asset...
		for i := range inscopeAssetsAsStrings {
			//write it to the output file
			_, err = f.WriteString(inscopeAssetsAsStrings[i] + "\n")
			if err != nil {
				crash("Unable to write to output file", err)
			}
		}

		//Process unsure assets
		if includeUnsure && unsureAssetsAsStrings != nil {
			//for each unsure asset...
			for i := range unsureAssetsAsStrings {
				//write it to the output file
				_, err = f.WriteString(unsureAssetsAsStrings[i] + "\n")
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

func parseAllScopes(inscopeScopes *[]interface{}, noscopeScopes *[]interface{}, targets *[]interface{}, explicitLevel *int) (inscopeAssets []interface{}, unsureAssets []interface{}) {
	// This function is where we'll implement the --include-unsure logic

	// For each target...
	for i := 0; i < len(*targets); i++ {
		target := (*targets)[i]
		targetIsInscope := isInscope(inscopeScopes, &target, explicitLevel)
		targetIsOutOfScope := isOutOfScope(noscopeScopes, &target, explicitLevel)

		if targetIsInscope && !targetIsOutOfScope {
			inscopeAssets = append(inscopeAssets, target)
		} else if includeUnsure {
			if !targetIsInscope && !targetIsOutOfScope {
				unsureAssets = append(inscopeAssets, target)
			}
		}

	}

	return inscopeAssets, unsureAssets
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
func isOutOfScope(noscopeScopes *[]interface{}, target *interface{}, explicitLevel *int) bool {
	//if we got no matches for any outOfScope
	return isInscope(noscopeScopes, target, explicitLevel)
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

// companyIndex is the numeric index of the company in the firebounty database, where 0 is the first company, 1 is the second company, etc
// Returns an error if no inscopeLines could be detected.
// Does not return an error if no noscopeLines could be detected.
func getCompanyScopes(firebountyJSON *Firebounty, companyIndex *int) (inscopeLines []string, noscopeLines []string, err error) {

	//match found!
	if !chainMode {

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
		fmt.Println("[+] Firebounty URL: " + firebountyJSON.Pgms[*companyIndex].Firebounty_url)
		fmt.Println("[+] Program URL: " + firebountyJSON.Pgms[*companyIndex].Url)

		// Print the in-scope rules
		fmt.Println("[+] In-scope rules: ")
		for _, inscope := range firebountyJSON.Pgms[*companyIndex].Scopes.In_scopes {
			fmt.Println("\t[+] " + inscope.Scope_type + ": " + inscope.Scope)
		}

		// Print the out-of-scope rules
		fmt.Println("\n[+] Out-of-scope rules: ")
		for _, noscope := range firebountyJSON.Pgms[*companyIndex].Scopes.Out_of_scopes {
			fmt.Println("\t[+] " + noscope.Scope_type + ": " + noscope.Scope)
		}

		fmt.Println("\n[+] Analysis started...")

	}

	//for every InScope Scope in the program
	for inscopeCounter := 0; inscopeCounter < len(firebountyJSON.Pgms[*companyIndex].Scopes.In_scopes); inscopeCounter++ {
		//if the scope type is "web_application" and it's not empty
		if firebountyJSON.Pgms[*companyIndex].Scopes.In_scopes[inscopeCounter].Scope_type == "web_application" && firebountyJSON.Pgms[*companyIndex].Scopes.In_scopes[inscopeCounter].Scope != "" {

			rawInScope := firebountyJSON.Pgms[*companyIndex].Scopes.In_scopes[inscopeCounter].Scope

			if !isAndroidPackageName(&rawInScope) {
				inscopeLines = append(inscopeLines, rawInScope)
			}

		}
	}

	if len(inscopeLines) == 0 {
		return nil, nil, errors.New("Unable to parse any inscopes scopes from " + firebountyJSON.Pgms[*companyIndex].Name)
	}

	//for every NoScope Scope in the program
	for noscopeCounter := 0; noscopeCounter < len(firebountyJSON.Pgms[*companyIndex].Scopes.Out_of_scopes); noscopeCounter++ {
		//if the scope type is "web_application" and it's not empty
		if firebountyJSON.Pgms[*companyIndex].Scopes.Out_of_scopes[noscopeCounter].Scope_type == "web_application" && firebountyJSON.Pgms[*companyIndex].Scopes.Out_of_scopes[noscopeCounter].Scope != "" {

			rawNoScope := firebountyJSON.Pgms[*companyIndex].Scopes.Out_of_scopes[noscopeCounter].Scope

			if !isAndroidPackageName(&rawNoScope) {
				noscopeLines = append(noscopeLines, rawNoScope)
			}

		}
	}

	return inscopeLines, noscopeLines, nil
}

// This function receives a raw scope string, and returns true if it's an android package name.
// It's goal is to help detect any misconfigured bug-bounty programs
// Only scopes that have the type "web_application" but that we aren't sure if they are actually web_application resources should be sent into this function.
// Sometimes bug bounty programs set APK package names such as com.my.businness.gatewayportal as web_application resources instead of as android_application resources in their program scope, causing trouble for anyone using automatic tools. Hacker-Scoper automatically detects these errors and notifies the user.
func isAndroidPackageName(rawScope *string) bool {

	// We begin the detection by trying to parse the given scope as an actual scope.
	// The problem with url.Parse is that it rarely returns an error. It often times assumes that invalid domain names (such as "this.is.not.avaliddomain") actually have a "private Top-Level-Domain". This is extremely unlikely in reality
	// TODO: Add a global switch you can specify to enable private TLDs.
	// TODO: Split parseLine into 3 functions, so we can directly try to parse the rawScope as a URL rather than wasting CPU cycles trying to parse CIDR Range -> IP Address -> URL.
	inscope, err := parseLine(*rawScope, true)

	if err != nil {
		warning("Error parsing \"" + *rawScope + "\".")
	} else if _, inscopeIsURL := inscope.(*url.URL); inscopeIsURL {
		// If the type of inscope is *url.URL ...
		portlessHostofCurrentTarget := removePortFromHost(inscope.(*url.URL))

		//alert the user about potentially mis-configured bug-bounty program
		_, scopeHasValidTLD := publicsuffix.PublicSuffix(portlessHostofCurrentTarget)

		if !chainMode {
			//alert the user about potentially mis-configured bug-bounty program
			if (*rawScope)[0:4] == "com." || (*rawScope)[0:4] == "org." {
				warning("The scope \"" + *rawScope + "\" starts with \"com.\" or \"org.\" This may be a sign of a misconfigured bug bounty program. Consider editing the \"" + firebountyJSONPath + " file and removing the faulty entries. Also, report the failure to the maintainers of the bug bounty program.")
			}
		}

		if !scopeHasValidTLD && inscope.(*url.URL).Host != "" {
			if !chainMode {
				warning("The scope \"" + *rawScope + "\" does not have a public Top Level Domain (TLD). This may be a sign of a misconfigured bug bounty program. Consider editing the \"" + firebountyJSONPath + " file and removing the faulty entries. Also, report the failure to the mainters of the bug bounty program.")
			}
			return true
		}
	}

	return false
}

// TODO: Add pre-compilation processing to remove this logic from the final exe.
func isVSCodeDebug() bool {
	// Set an environment variable in your VS Code launch config, e.g. "VSCODE_DEBUG=true"
	return os.Getenv("VSCODE_DEBUG") == "true"
}

// This function receives a filepath as a string, and returns a string with the contents of the file
// All lines are trimmed, and empty lines are removed
// All lines beginning with '#' or '//' are considered comments and are removed
func readFileLines(filepath string) ([]string, error) {
	file, err := os.Open(filepath) // #nosec G304 -- filepath is a CLI argument specified by the user running the program. It is not unsafe to allow them to open any file in their own system.
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "//") {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// If isScope is true, ParseLine attempts to parse a string into either:
// - *net.IPNet		(CIDR notation)
// - *net.IP		(single IP address)
// - *url.URL 		(valid URL)
// - *regexp.Regexp (Regex)
//
// If isScope is false, ParseLine attempts to parse a string into either:
// - *net.IP	(single IP address)
// - *url.URL	(valid URL)
//
// This function returns the error ErrInvalidFormat if the string didn't match any of the listed formats.
func parseLine(line string, isScope bool) (interface{}, error) {

	// TODO: Fix CIDR detection of IPv6 CIDR ranges. For some reason they're detected as URLs instead of as CIDR ranges.

	// TODO: Add a --optimize flag that when enabled will save all of the inscope, and noscope scopes in a separate file, with their type already determined, so we don't have to waste time guessing the scope type every time hacker-scoper is run. Maybe in CSV format. We could also use the file last-modified-at metadata to know whether the .inscope and .noscope files were modified. The --optimize flag should only have an effect when hacker-scoper is ran with .inscope and .noscope files, or with the firebounty db.It wouldn't make sense to optimize the input of stdin.

	if isScope {
		// Try CIDR first (most specific)
		if _, ipnet, err := net.ParseCIDR(line); err == nil {
			return ipnet, nil
		}
	}

	// Try plain IP
	if ip := net.ParseIP(line); ip != nil {
		return &ip, nil
	}

	// If the line is a scope and contains a wildcard...
	if isScope && strings.Contains(line, "*") {

		// Attempt to parse the scope as a regex
		rawRegex := strings.Replace(line, ".", "\\.", -1)
		rawRegex = strings.Replace(rawRegex, "*", ".*", -1)

		scopeRegex, err := regexp.Compile(rawRegex)
		if err != nil {
			if chainMode {
				warning("There was an error parsing the scope \"" + line + "\" (converted into \"" + rawRegex + "\") as a regex. This scope was parsed as a regex instead of as a URL because it has 1 or more wildcards.")
			}
			return nil, ErrInvalidFormat
		} else {
			return scopeRegex, nil
		}
	}

	// Try URL (with basic validation)
	parsedURL, err := url.Parse(line)
	if err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
		return parsedURL, nil
	} else {
		// Retry parsing but with a 'https://' prefix
		parsedURL, err := url.Parse("https://" + line)
		if err == nil && parsedURL.Scheme != "" && parsedURL.Host != "" {
			return parsedURL, nil
		} else {
			return nil, ErrInvalidFormat
		}
	}
}

// ParseAllLines processes each line individually, returning:
// - A slice of parsed objects (interface{} holding *net.IPNet, net.IP, or *url.URL)
// - An error if no lines could be parsed as a scope, otherwise nil.
// isScopes should be true if the lines to be parsed are scopes.
func parseAllLines(lines []string, isScopes bool) ([]interface{}, error) {
	parsed := []interface{}{}

	for i, line := range lines {
		parsedTemp, err := parseLine(line, isScopes)
		if err != nil {
			warning("Unable to parse line number " + strconv.Itoa(i) + " as a scope: \"" + line + "\"")
		} else {
			parsed = append(parsed, parsedTemp)
		}

	}

	if len(parsed) == 0 {
		return nil, errors.New("unable to parse any lines as scopes")
	} else {
		return parsed, nil
	}

}

// This function is needed to convert all of the arrays of interfaces into arrays of strings, so that they can be easily processed at the end of the program.
func interfaceToStrings(interfaces *[]interface{}, isScope bool) (strings []string) {

	if isScope {
		// For each interface in interfaces...
		for i := 0; i < len(*interfaces); i++ {
			switch v := (*interfaces)[i].(type) {
			case *net.IPNet:
				// If it's a CIDR network...
				//strings = append(strings, (*interfaces)[i].(*net.IPNet).String())
				strings = append(strings, v.String())
			case *net.IP:
				// If it's an IP Address
				//strings = append(strings, (*interfaces)[i].(*net.IP).String())
				strings = append(strings, v.String())
			case *url.URL:
				// If it's a URL...
				//strings = append(strings, (*interfaces)[i].(*url.URL).String())
				strings = append(strings, v.String())
			case *regexp.Regexp:
				// If it's a regex...
				//strings = append(strings, (*interfaces)[i].(*regexp.Regexp).String())
				strings = append(strings, v.String())
			}
		}
	} else {
		// If the given interfaces are not scopes, they are targets. Targets are never CIDR ranges, or regular expressions.
		// For each interface in interfaces...
		for i := 0; i < len(*interfaces); i++ {
			switch assertedInterface := (*interfaces)[i].(type) {
			case *net.IP:
				// If it's an IP Address
				//strings = append(strings, (*interfaces)[i].(*net.IP).String())
				strings = append(strings, assertedInterface.String())
			case *url.URL:
				// If it's a URL...
				//strings = append(strings, (*interfaces)[i].(*url.URL).String())
				strings = append(strings, assertedInterface.String())
			}
		}
	}
	return strings
}

func isInscope(inscopeScopes *[]interface{}, target *interface{}, explicitLevel *int) (result bool) {

	// Here we use a switch-case on the type of target. So target is processed differently depending on which variable type it is.

	switch assertedTarget := (*target).(type) {
	// If the target is an IP Address...
	case *net.IP:
		// For each scope in inscopeScopes...
		for i := 0; i < len(*inscopeScopes); i++ {
			// We're only interested in comparing IP targets against CIDR networks and IP addresses.
			switch assertedScope := (*inscopeScopes)[i].(type) {
			// If the i scope is a CIDR network...
			case *net.IPNet:
				result = assertedScope.Contains(*assertedTarget)

			// If the i scope is an IP Address...
			case *net.IP:
				result = assertedScope.Equal(*assertedTarget)

				// TODO: Add a regex case for comparing against target IP addresses
			}
			if result {
				return result
			}
		}

	// If the target is a URL...
	case *url.URL:
		for i := 0; i < len(*inscopeScopes); i++ {
			// We're only interested in comparing URL targets against URL scopes, and regex.
			switch assertedScope := (*inscopeScopes)[i].(type) {
			// If the i scope is a URL...
			case *url.URL:
				switch *explicitLevel {
				case 1:
					//if x is a subdomain of y
					//ex: wordpress.example.com with a scope of *.example.com will give a match
					//we DON'T do it by splitting on dots and matching, because that would cause errors with domains that have two top-level-domains (gov.br for example)
					result = strings.HasSuffix(removePortFromHost(assertedTarget), assertedScope.Host)

				// case 2:
				// --explicit-level=2 is handled in the case the current scope is a regex. This is because all scopes that have wildcards in them, are automatically turned into regular expressions.

				case 3:
					result = removePortFromHost(assertedTarget) == assertedScope.Host
				}

			case *regexp.Regexp:
				if *explicitLevel != 3 {
					// If the i scope is a regex...
					//if the current target host matches the regex...
					result = assertedScope.MatchString(removePortFromHost(assertedTarget))
				}
			}
			if result {
				return result
			}
		}
	}

	return false
}
