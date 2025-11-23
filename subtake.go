package main

import (
    "bufio"
    "crypto/tls"
    "encoding/json"
    "flag"
    "fmt"
    "net"
    "net/http"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"

    "github.com/fatih/color"
    "github.com/valyala/fasthttp"
)

// Configuration structure
type Config struct {
    Threads           int      `json:"threads"`
    Timeout           int      `json:"timeout"`
    UserAgent         string   `json:"user_agent"`
    FollowRedirects   bool     `json:"follow_redirects"`
    VerifySSL         bool     `json:"verify_ssl"`
    DeepCheck         bool     `json:"deep_check"`
    OutputFile        string   `json:"output_file"`
    CustomSignatures  []string `json:"custom_signatures"`
}

// Result structure
type Result struct {
    Subdomain    string `json:"subdomain"`
    CNAME        string `json:"cname"`
    Service      string `json:"service"`
    Status       string `json:"status"`
    Confidence   string `json:"confidence"`
    Evidence     string `json:"evidence"`
    IP           string `json:"ip"`
    ResponseTime int64  `json:"response_time"`
}

// Service signatures
type ServiceSignature struct {
    Service     string   `json:"service"`
    CNAMES      []string `json:"cnames"`
    Fingerprint string   `json:"fingerprint"`
    StatusCode  int      `json:"status_code"`
    BodyMatch   string   `json:"body_match"`
    HeaderMatch string   `json:"header_match"`
    Confidence  string   `json:"confidence"`
}

var (
    config      Config
    signatures  []ServiceSignature
    client      *fasthttp.Client
    httpClient  *http.Client
    results     []Result
    resultsLock sync.Mutex
    red         = color.New(color.FgRed).SprintFunc()
    green       = color.New(color.FgGreen).SprintFunc()
    yellow      = color.New(color.FgYellow).SprintFunc()
    blue        = color.New(color.FgBlue).SprintFunc()
    cyan        = color.New(color.FgCyan).SprintFunc()
)

func init() {
    // Default configuration
    config = Config{
        Threads:         50,
        Timeout:         10,
        UserAgent:       "SubTake/v2.0",
        FollowRedirects: true,
        VerifySSL:       false,
        DeepCheck:       true,
        OutputFile:      "",
    }

    // Initialize HTTP clients
    client = &fasthttp.Client{
        ReadTimeout:                   time.Duration(config.Timeout) * time.Second,
        WriteTimeout:                  time.Duration(config.Timeout) * time.Second,
        MaxConnsPerHost:               100,
        TLSConfig:                     &tls.Config{InsecureSkipVerify: !config.VerifySSL},
        DisableHeaderNamesNormalizing: true,
    }

    httpClient = &http.Client{
        Timeout: time.Duration(config.Timeout) * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: !config.VerifySSL},
        },
    }

    loadSignatures()
}

func loadSignatures() {
    // Comprehensive service signatures
    signatures = []ServiceSignature{
        {
            Service:    "AWS S3",
            CNAMES:     []string{".s3.amazonaws.com", ".s3-website", ".s3."},
            Fingerprint: "NoSuchBucket",
            StatusCode:  404,
            BodyMatch:   "NoSuchBucket|No Such Bucket",
            Confidence:  "high",
        },
        {
            Service:    "GitHub Pages",
            CNAMES:     []string{".github.io", ".github.com"},
            Fingerprint: "There isn't a GitHub Pages site here",
            StatusCode:  404,
            BodyMatch:   "There isn't a GitHub Pages site here",
            Confidence:  "high",
        },
        {
            Service:    "Heroku",
            CNAMES:     []string{".herokuapp.com", ".herokudns.com"},
            Fingerprint: "No such app",
            StatusCode:  404,
            BodyMatch:   "No such app|heroku|Heroku",
            Confidence:  "high",
        },
        {
            Service:    "Shopify",
            CNAMES:     []string{".myshopify.com"},
            Fingerprint: "Sorry, this shop is currently unavailable",
            StatusCode:  404,
            BodyMatch:   "Sorry, this shop is currently unavailable",
            Confidence:  "high",
        },
        {
            Service:    "Fastly",
            CNAMES:     []string{".fastly.net", ".fastly."},
            Fingerprint: "Fastly error|404 Not Found",
            StatusCode:  404,
            BodyMatch:   "Fastly error",
            Confidence:  "medium",
        },
        {
            Service:    "Azure",
            CNAMES:     []string{".azurewebsites.net", ".cloudapp.azure.com"},
            Fingerprint: "Azure",
            StatusCode:  404,
            BodyMatch:   "Microsoft Azure|Azure",
            Confidence:  "medium",
        },
        {
            Service:    "Google Cloud",
            CNAMES:     []string{".appspot.com", ".cloud.goog", ".googleusercontent.com"},
            Fingerprint: "Google Cloud",
            StatusCode:  404,
            BodyMatch:   "Google Cloud|The requested URL was not found",
            Confidence:  "medium",
        },
        {
            Service:    "Firebase",
            CNAMES:     []string{".web.app", ".firebaseapp.com"},
            Fingerprint: "Firebase",
            StatusCode:  404,
            BodyMatch:   "Firebase|The requested URL was not found",
            Confidence:  "high",
        },
        {
            Service:    "CloudFront",
            CNAMES:     []string{".cloudfront.net"},
            Fingerprint: "CloudFront",
            StatusCode:  404,
            BodyMatch:   "CloudFront|ERROR: The request could not be satisfied",
            HeaderMatch: "X-Cache: Error from cloudfront",
            Confidence:  "high",
        },
        {
            Service:    "AWS Elastic Beanstalk",
            CNAMES:     []string{".elasticbeanstalk.com"},
            Fingerprint: "AWS Elastic Beanstalk",
            StatusCode:  404,
            BodyMatch:   "AWS Elastic Beanstalk",
            Confidence:  "medium",
        },
        {
            Service:    "Bitbucket",
            CNAMES:     []string{".bitbucket.io"},
            Fingerprint: "Bitbucket",
            StatusCode:  404,
            BodyMatch:   "Bitbucket|Repository not found",
            Confidence:  "high",
        },
        {
            Service:    "Readme.io",
            CNAMES:     []string{".readme.io", ".readme.com"},
            Fingerprint: "Readme",
            StatusCode:  404,
            BodyMatch:   "Readme|Project doesnt exist",
            Confidence:  "high",
        },
        {
            Service:    "Intercom",
            CNAMES:     []string{".intercom.help", ".intercom.io"},
            Fingerprint: "Intercom",
            StatusCode:  404,
            BodyMatch:   "Intercom|This page is not on Intercom",
            Confidence:  "high",
        },
        {
            Service:    "Help Scout",
            CNAMES:     []string{".helpscoutdocs.com", ".helpscout.com"},
            Fingerprint: "Help Scout",
            StatusCode:  404,
            BodyMatch:   "Help Scout|No settings were found for this company",
            Confidence:  "high",
        },
        {
            Service:    "Ghost.io",
            CNAMES:     []string{".ghost.io"},
            Fingerprint: "Ghost",
            StatusCode:  404,
            BodyMatch:   "Ghost|The blog you were looking for was not found",
            Confidence:  "high",
        },
        {
            Service:    "Pantheon",
            CNAMES:     []string{".pantheonsite.io", ".pantheon.io"},
            Fingerprint: "Pantheon",
            StatusCode:  404,
            BodyMatch:   "Pantheon|The gods are wise",
            Confidence:  "high",
        },
        {
            Service:    "Tilda",
            CNAMES:     []string{".tilda.ws", ".tilda.com"},
            Fingerprint: "Tilda",
            StatusCode:  404,
            BodyMatch:   "Tilda|Please renew your subscription",
            Confidence:  "high",
        },
        {
            Service:    "WordPress.com",
            CNAMES:     []string{".wordpress.com", ".wp.com"},
            Fingerprint: "WordPress",
            StatusCode:  404,
            BodyMatch:   "WordPress|This site is not available",
            Confidence:  "high",
        },
        {
            Service:    "Zendesk",
            CNAMES:     []string{".zendesk.com", ".zendesk.com"},
            Fingerprint: "Zendesk",
            StatusCode:  404,
            BodyMatch:   "Zendesk|Help Center Closed",
            Confidence:  "high",
        },
        {
            Service:    "Unbounce",
            CNAMES:     []string{".unbounce.com"},
            Fingerprint: "Unbounce",
            StatusCode:  404,
            BodyMatch:   "Unbounce|The requested URL was not found",
            Confidence:  "high",
        },
        {
            Service:    "Surge.sh",
            CNAMES:     []string{".surge.sh"},
            Fingerprint: "Surge",
            StatusCode:  404,
            BodyMatch:   "Surge|project not found",
            Confidence:  "high",
        },
        {
            Service:    "Netlify",
            CNAMES:     []string{".netlify.app", ".netlify.com"},
            Fingerprint: "Netlify",
            StatusCode:  404,
            BodyMatch:   "Netlify|Not Found - Request ID",
            Confidence:  "high",
        },
        {
            Service:    "Launchrock",
            CNAMES:     []string{".launchrock.com"},
            Fingerprint: "Launchrock",
            StatusCode:  404,
            BodyMatch:   "Launchrock|It appears that you don't have a LaunchRock site",
            Confidence:  "high",
        },
        {
            Service:    "Aftership",
            CNAMES:     []string{".aftership.com"},
            Fingerprint: "Aftership",
            StatusCode:  404,
            BodyMatch:   "Aftership|Oops! The page you're looking for doesn't exist",
            Confidence:  "high",
        },
        {
            Service:    "Cargo Collective",
            CNAMES:     []string{".cargocollective.com"},
            Fingerprint: "Cargo",
            StatusCode:  404,
            BodyMatch:   "Cargo|404 Not Found",
            Confidence:  "medium",
        },
        {
            Service:    "Feedpress",
            CNAMES:     []string{".feedpress.com"},
            Fingerprint: "Feedpress",
            StatusCode:  404,
            BodyMatch:   "Feedpress|The feed has not been found",
            Confidence:  "high",
        },
        {
            Service:    "Freshdesk",
            CNAMES:     []string{".freshdesk.com"},
            Fingerprint: "Freshdesk",
            StatusCode:  404,
            BodyMatch:   "Freshdesk|Sorry, this page is no longer available",
            Confidence:  "high",
        },
        {
            Service:    "Gemfury",
            CNAMES:     []string{".fury.io", ".gemfury.com"},
            Fingerprint: "Gemfury",
            StatusCode:  404,
            BodyMatch:   "Gemfury|404 Not Found",
            Confidence:  "medium",
        },
        {
            Service:    "Help Juice",
            CNAMES:     []string{".helpjuice.com"},
            Fingerprint: "Help Juice",
            StatusCode:  404,
            BodyMatch:   "Help Juice|We could not find what you're looking for",
            Confidence:  "high",
        },
        {
            Service:    "Help Docs",
            CNAMES:     []string{".helpdocs.io"},
            Fingerprint: "Help Docs",
            StatusCode:  404,
            BodyMatch:   "Help Docs|The knowledge base you are looking for does not exist",
            Confidence:  "high",
        },
        {
            Service:    "Instapage",
            CNAMES:     []string{".pageserve.co", ".secure.pageserve.co"},
            Fingerprint: "Instapage",
            StatusCode:  404,
            BodyMatch:   "Instapage|The page you are looking for doesn't exist",
            Confidence:  "high",
        },
        {
            Service:    "Smartling",
            CNAMES:     []string{".smartling.com"},
            Fingerprint: "Smartling",
            StatusCode:  404,
            BodyMatch:   "Smartling|The specified project does not exist",
            Confidence:  "high",
        },
        {
            Service:    "Statuspage",
            CNAMES:     []string{".statuspage.io"},
            Fingerprint: "Statuspage",
            StatusCode:  404,
            BodyMatch:   "Statuspage|You are being redirected",
            Confidence:  "medium",
        },
        {
            Service:    "Thinkific",
            CNAMES:     []string{".thinkific.com"},
            Fingerprint: "Thinkific",
            StatusCode:  404,
            BodyMatch:   "Thinkific|The page you were looking for doesn't exist",
            Confidence:  "high",
        },
        {
            Service:    "Tumblr",
            CNAMES:     []string{".tumblr.com"},
            Fingerprint: "Tumblr",
            StatusCode:  404,
            BodyMatch:   "Tumblr|There's nothing here",
            Confidence:  "high",
        },
        {
            Service:    "UserVoice",
            CNAMES:     []string{".uservoice.com"},
            Fingerprint: "UserVoice",
            StatusCode:  404,
            BodyMatch:   "UserVoice|This site is not available",
            Confidence:  "high",
        },
        {
            Service:    "WordPress VIP",
            CNAMES:     []string{".wpcomstaging.com"},
            Fingerprint: "WordPress VIP",
            StatusCode:  404,
            BodyMatch:   "WordPress VIP|This site is not available",
            Confidence:  "high",
        },
        {
            Service:    "Worksites",
            CNAMES:     []string{".worksites.net"},
            Fingerprint: "Worksites",
            StatusCode:  404,
            BodyMatch:   "Worksites|Site Not Found",
            Confidence:  "high",
        },
        {
            Service:    "Agile CRM",
            CNAMES:     []string{".agilecrm.com"},
            Fingerprint: "Agile CRM",
            StatusCode:  404,
            BodyMatch:   "Agile CRM|Sorry, this page is no longer available",
            Confidence:  "high",
        },
    }
}

func main() {
    var targetFile, singleTarget, outputFile string
    var threads, timeout int
    var verbose, verifySSL, deepCheck, jsonOutput bool

    flag.StringVar(&targetFile, "f", "", "File containing list of subdomains")
    flag.StringVar(&singleTarget, "d", "", "Single target subdomain")
    flag.StringVar(&outputFile, "o", "", "Output file to save results")
    flag.IntVar(&threads, "t", 50, "Number of concurrent threads")
    flag.IntVar(&timeout, "timeout", 10, "Timeout in seconds")
    flag.BoolVar(&verbose, "v", false, "Verbose output")
    flag.BoolVar(&verifySSL, "ssl", false, "Verify SSL certificates")
    flag.BoolVar(&deepCheck, "deep", true, "Perform deep checking")
    flag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
    flag.Parse()

    // Update configuration
    config.Threads = threads
    config.Timeout = timeout
    config.VerifySSL = verifySSL
    config.DeepCheck = deepCheck
    config.OutputFile = outputFile

    // Banner
    printBanner()

    // Validate input
    if targetFile == "" && singleTarget == "" {
        color.Red("[-] Error: Please provide either a file with -f or a single target with -d")
        flag.Usage()
        os.Exit(1)
    }

    var targets []string

    // Read targets from file or single target
    if targetFile != "" {
        targets = readTargetsFromFile(targetFile)
        color.Cyan("[+] Loaded %d targets from file: %s", len(targets), targetFile)
    } else {
        targets = []string{singleTarget}
        color.Cyan("[+] Testing single target: %s", singleTarget)
    }

    color.Cyan("[+] Starting SubTake v2.0 with %d threads", config.Threads)
    color.Cyan("[+] Timeout: %d seconds", config.Timeout)
    color.Cyan("[+] Deep Check: %v", config.DeepCheck)
    color.Cyan("[+] SSL Verification: %v", config.VerifySSL)

    // Process targets
    processTargets(targets, verbose)

    // Print results
    printResults(jsonOutput)

    // Save results if output file specified
    if outputFile != "" {
        saveResults(outputFile, jsonOutput)
    }
}

func readTargetsFromFile(filename string) []string {
    var targets []string
    file, err := os.Open(filename)
    if err != nil {
        color.Red("[-] Error opening file: %v", err)
        os.Exit(1)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        target := strings.TrimSpace(scanner.Text())
        if target != "" {
            targets = append(targets, target)
        }
    }

    if err := scanner.Err(); err != nil {
        color.Red("[-] Error reading file: %v", err)
        os.Exit(1)
    }

    return targets
}

func processTargets(targets []string, verbose bool) {
    var wg sync.WaitGroup
    semaphore := make(chan struct{}, config.Threads)

    color.Cyan("[+] Processing %d targets...", len(targets))

    for _, target := range targets {
        wg.Add(1)
        semaphore <- struct{}{}

        go func(t string) {
            defer wg.Done()
            defer func() { <-semaphore }()

            if verbose {
                color.Yellow("[~] Checking: %s", t)
            }

            result := checkSubdomain(t)
            if result.Status != "" {
                resultsLock.Lock()
                results = append(results, result)
                resultsLock.Unlock()

                printResult(result)
            }
        }(target)
    }

    wg.Wait()
}

func checkSubdomain(subdomain string) Result {
    result := Result{
        Subdomain: subdomain,
        Status:    "safe",
    }

    // Step 1: CNAME lookup
    cname, err := net.LookupCNAME(subdomain)
    if err != nil {
        return result
    }

    result.CNAME = cname

    // Step 2: IP lookup
    ips, err := net.LookupIP(subdomain)
    if err == nil && len(ips) > 0 {
        result.IP = ips[0].String()
    }

    // Step 3: Check against service signatures
    for _, signature := range signatures {
        if matchesCNAME(cname, signature.CNAMES) {
            result.Service = signature.Service
            result.Confidence = signature.Confidence

            // Step 4: HTTP verification for deep check
            if config.DeepCheck {
                if verifyWithHTTP(subdomain, signature, &result) {
                    result.Status = "vulnerable"
                    break
                }
            } else {
                result.Status = "potentially_vulnerable"
                result.Evidence = "CNAME match only"
            }
        }
    }

    return result
}

func matchesCNAME(cname string, patterns []string) bool {
    for _, pattern := range patterns {
        if strings.Contains(cname, pattern) {
            return true
        }
    }
    return false
}

func verifyWithHTTP(subdomain string, signature ServiceSignature, result *Result) bool {
    start := time.Now()
    
    urls := []string{
        fmt.Sprintf("https://%s", subdomain),
        fmt.Sprintf("http://%s", subdomain),
    }

    for _, testURL := range urls {
        req := fasthttp.AcquireRequest()
        resp := fasthttp.AcquireResponse()
        defer fasthttp.ReleaseRequest(req)
        defer fasthttp.ReleaseResponse(resp)

        req.SetRequestURI(testURL)
        req.Header.SetMethod("GET")
        req.Header.SetUserAgent(config.UserAgent)

        err := client.Do(req, resp)
        if err != nil {
            continue
        }

        result.ResponseTime = time.Since(start).Milliseconds()

        body := string(resp.Body())
        statusCode := resp.StatusCode()

        // Check status code
        if signature.StatusCode != 0 && statusCode == signature.StatusCode {
            result.Evidence = fmt.Sprintf("Status: %d", statusCode)
        }

        // Check body content
        if signature.BodyMatch != "" {
            matched, _ := regexp.MatchString(signature.BodyMatch, body)
            if matched {
                result.Evidence += " | Body match"
                return true
            }
        }

        // Check headers
        if signature.HeaderMatch != "" {
            headers := make(map[string]string)
            resp.Header.VisitAll(func(key, value []byte) {
                headers[string(key)] = string(value)
            })

            for key, value := range headers {
                if strings.Contains(key+":"+value, signature.HeaderMatch) {
                    result.Evidence += " | Header match"
                    return true
                }
            }
        }

        // If we have status code match and no specific body/header requirements
        if signature.StatusCode != 0 && statusCode == signature.StatusCode && signature.BodyMatch == "" {
            return true
        }
    }

    return false
}

func printResult(result Result) {
    switch result.Status {
    case "vulnerable":
        color.Red("[VULNERABLE] %s -> %s (%s) [%s] %s", 
            result.Subdomain, result.CNAME, result.Service, result.Confidence, result.Evidence)
    case "potentially_vulnerable":
        color.Yellow("[POTENTIAL] %s -> %s (%s) [%s]", 
            result.Subdomain, result.CNAME, result.Service, result.Confidence)
    }
}

func printResults(jsonOutput bool) {
    color.Cyan("\n[+] Scan completed!")
    color.Cyan("[+] Total targets processed: %d", len(results))
    
    vulnerable := 0
    potential := 0
    
    for _, result := range results {
        if result.Status == "vulnerable" {
            vulnerable++
        } else if result.Status == "potentially_vulnerable" {
            potential++
        }
    }
    
    color.Red("[+] Vulnerable: %d", vulnerable)
    color.Yellow("[+] Potential: %d", potential)
    color.Green("[+] Safe: %d", len(results)-vulnerable-potential)

    if jsonOutput {
        jsonData, _ := json.MarshalIndent(results, "", "  ")
        fmt.Println(string(jsonData))
    }
}

func saveResults(filename string, jsonOutput bool) {
    file, err := os.Create(filename)
    if err != nil {
        color.Red("[-] Error creating output file: %v", err)
        return
    }
    defer file.Close()

    if jsonOutput {
        jsonData, _ := json.MarshalIndent(results, "", "  ")
        file.Write(jsonData)
    } else {
        writer := bufio.NewWriter(file)
        for _, result := range results {
            line := fmt.Sprintf("%s,%s,%s,%s,%s,%s\n",
                result.Subdomain, result.CNAME, result.Service, result.Status, result.Confidence, result.Evidence)
            writer.WriteString(line)
        }
        writer.Flush()
    }

    color.Green("[+] Results saved to: %s", filename)
}

func printBanner() {
    banner := `
    ███████╗██╗   ██╗██████╗ ████████╗ █████╗ ██╗  ██╗███████╗
    ██╔════╝██║   ██║██╔══██╗╚══██╔══╝██╔══██╗██║ ██╔╝██╔════╝
    ███████╗██║   ██║██████╔╝   ██║   ███████║█████╔╝ █████╗  
    ╚════██║██║   ██║██╔══██╗   ██║   ██╔══██║██╔═██╗ ██╔══╝  
    ███████║╚██████╔╝██████╔╝   ██║   ██║  ██║██║  ██╗███████╗
    ╚══════╝ ╚═════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                        
        SubTake v9.10 - Subdomain Takeover Scanner
                Developed by Mr Monsif 
    `
    color.Cyan(banner)
}