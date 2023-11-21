package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ghodss/yaml"
	"github.com/google/go-github/v50/github"
	"github.com/stackrox/dotnet-scraper/types"
	"golang.org/x/time/rate"
)

type repoReference struct {
	owner, name string
}

const (
	pageSize = 20
)

var (
	cveRegex = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
)

var repos = []repoReference{
	{
		owner: "dotnet",
		name:  "announcements",
	},
	{
		owner: "aspnet",
		name:  "Announcements",
	},
}

// knownMissingLinks are links that exist in the github repos, but are not referred to by the YAML files
// this can be due to duplicate CVE definitions between dotnet and aspnet, issues that don't have CVEs attributed
// and advisories that are irrelevant
var knownMissingLinks = []string{
	// ASP.NET Announcement Repo

	// Microsoft Security Advisory: iOS12 breaks social, WSFed and OIDC logins #318
	"https://github.com/aspnet/Announcements/issues/318",
	// Microsoft Security Advisory ASPNETCore-July18: ASP.NET Core Denial Of Service Vulnerability
	"https://github.com/aspnet/Announcements/issues/311",
	// Microsoft Security Advisory ASPNETCore-Mar18: ASP.NET Core Denial Of Service Vulnerability
	"https://github.com/aspnet/Announcements/issues/300",
	// Microsoft Security Advisory CVE-2019-0815: ASP.NET Core denial of service vulnerability
	// Strange module
	"https://github.com/aspnet/Announcements/issues/352",
	// Microsoft Security Advisory 4021279: Vulnerabilities in .NET Core, ASP.NET Core Could Allow Elevation of Privilege
	// Duplicate of https://github.com/dotnet/announcements/issues/12
	"https://github.com/aspnet/Announcements/issues/239",
	// Microsoft Security Advisory CVE-2018-0808: ASP.NET Core Denial Of Service Vulnerability
	// IIS vuln
	"https://github.com/aspnet/Announcements/issues/294",
	// Microsoft Security Advisory CVE-2019-0548: ASP.NET Core Denial Of Service Vulnerability
	// IIS vuln
	"https://github.com/aspnet/Announcements/issues/335",
	// Ignoring MSAs for now
	"https://github.com/aspnet/Announcements/issues/203",
	"https://github.com/aspnet/Announcements/issues/216",
	// Affects .NET SDK
	"https://github.com/aspnet/Announcements/issues/284",
	"https://github.com/aspnet/Announcements/issues/285",

	// Affects MVC in version <2.1 (could not download 2.0 on Linux)
	"https://github.com/aspnet/Announcements/issues/278",

	// Affects MVC in version <2.1 (could not download 2.0 on Linux)
	"https://github.com/aspnet/Announcements/issues/279",

	// Affects MessagePack which is a non-runtime package
	"https://github.com/aspnet/Announcements/issues/359",
	"https://github.com/aspnet/Announcements/issues/405",

	// .NET Announcement Repo

	// Microsoft Security Advisory CVE-2020-1597 | ASP.NET Core Denial of Service Vulnerability
	// Duplicate https://github.com/aspnet/Announcements/issues/431
	"https://github.com/dotnet/announcements/issues/162",
	// Microsoft Security Advisory CVE-2018-8409: .NET Core Denial Of Service Vulnerability
	// Duplicate https://github.com/aspnet/Announcements/issues/316
	"https://github.com/dotnet/announcements/issues/83",
	// Microsoft Security Advisory CVE-2020-1108 | .NET Core Denial of Service Vulnerability
	// Duplicate of https://github.com/dotnet/announcements/issues/157
	"https://github.com/dotnet/announcements/issues/156",

	// Affects .NET 1
	"https://github.com/dotnet/announcements/issues/12",

	// Affects service model and not the core runtime
	"https://github.com/dotnet/announcements/issues/73",

	// Duplicate of https://github.com/aspnet/Announcements/issues/449
	"https://github.com/dotnet/announcements/issues/170",

	// Affects System.DirectoryServices.Protocols, which is not generically fixed by upgrading .NET core
	"https://github.com/dotnet/announcements/issues/202",

	// Vulnerability only affects IIS hosted applications which is not available on Linux
	"https://github.com/dotnet/announcements/issues/206",

	// Vulnerability only affects NuGet packages
	"https://github.com/dotnet/announcements/issues/239",

	// Duplicate of https://github.com/dotnet/announcements/issues/250
	"https://github.com/dotnet/announcements/issues/258",

	// Duplicate of https://github.com/dotnet/announcements/issues/282
	"https://github.com/dotnet/announcements/issues/277",

	// Duplicate of https://github.com/dotnet/announcements/issues/281
	"https://github.com/dotnet/announcements/issues/278",

	// Duplicate of https://github.com/dotnet/announcements/issues/280
	"https://github.com/dotnet/announcements/issues/279",

	// Only affects release candidates for .NET 8.0, ACS Scanner's analyzer currently
	// ignores release candidate versions.  More info here:
	// https://github.com/stackrox/dotnet-scraper/pull/38#pullrequestreview-1700612216
	"https://github.com/dotnet/announcements/issues/286",
}

type linkRef struct {
	stillNeeded bool
	cve         string
}

func main() {
	client := github.NewClient(nil)

	issueLinks := make(map[string]*linkRef)
	for _, repo := range repos {
		var issues []*github.Issue
		var page int
		for {
			pagedIssues, _, err := client.Issues.ListByRepo(context.Background(), repo.owner, repo.name, &github.IssueListByRepoOptions{
				Labels: []string{"security"},
				ListOptions: github.ListOptions{
					Page:    page,
					PerPage: pageSize,
				},
			})
			if err != nil {
				log.Fatalf("Could not fetch issues for %s/%s: %v", repo.owner, repo.name, err)
			}
			page++
			issues = append(issues, pagedIssues...)
			if len(pagedIssues) != pageSize {
				break
			}
		}

		for _, issue := range issues {
			title := strings.TrimSpace(issue.GetTitle())
			if !strings.HasPrefix(title, "Microsoft Security Advisory") {
				continue
			}
			var cve string
			if cveMatches := cveRegex.FindStringSubmatch(title); len(cveMatches) > 0 {
				cve = cveMatches[0]
			}

			link := strings.ReplaceAll(issue.GetURL(), "api.github.com/repos", "github.com")
			issueLinks[link] = &linkRef{
				stillNeeded: true,
				cve:         cve,
			}
		}
	}

	root := "cves"
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if filepath.Ext(info.Name()) == ".yaml" {
			bytes, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			var cd types.CVEDefinition
			if err := yaml.Unmarshal(bytes, &cd); err != nil {
				return fmt.Errorf("unmarshalling %s: %w", info.Name(), err)
			}
			_, ok := issueLinks[cd.Link]
			if !ok {
				log.Fatalf("unknown link %v - %v", cd.Link, info.Name())
			} else {
				issueLinks[cd.Link].stillNeeded = false
			}
		}
		return nil
	})
	if err != nil {
		log.Fatalf("error walking cve dir: %v", err)
	}

	// Remove all known missing links. Why the links are missing should be next to their declaration
	for _, knownMissing := range knownMissingLinks {
		delete(issueLinks, knownMissing)
	}

	// NVD API rate limits requests to 5 per 30-second window.
	// See https://nvd.nist.gov/developers/start-here for more
	// information.
	l := rate.NewLimiter(rate.Every(6*time.Second), 1)

	// Iterate over missing issue links and see if CVE is valid
	for link, linkRef := range issueLinks {
		err := l.Wait(context.Background())
		if err != nil {
			log.Fatalf("waiting for rate limit: %v", err)
		}
		if linkRef.stillNeeded && linkRef.cve != "" {
			valid, err := validateNVDCVEIsEvaluated(linkRef.cve)
			if err != nil {
				log.Fatalf("could not validate NVD CVE %s: %v", linkRef.cve, err)
			}
			if !valid {
				delete(issueLinks, link)
			}
		}
	}

	if len(issueLinks) > 0 {
		fail := false
		for link, linkRef := range issueLinks {
			if linkRef.stillNeeded {
				fail = true
				log.Printf("Unaccounted for issue: %v", link)
			}
		}
		if fail {
			log.Fatalf("Failing with non 0 exit code")
		}
	}
}
