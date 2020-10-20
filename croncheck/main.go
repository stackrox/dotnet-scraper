package main

import (
	"context"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghodss/yaml"
	"github.com/google/go-github/v32/github"
	"github.com/stackrox/dotnet-scraper/types"
)

type repoReference struct {
	owner, name string
}

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

var knownMissingLinks = []string{
	"https://github.com/aspnet/Announcements/issues/405",
	"https://github.com/aspnet/Announcements/issues/318",
	"https://github.com/aspnet/Announcements/issues/311",
	"https://github.com/aspnet/Announcements/issues/300",
	"https://github.com/dotnet/announcements/issues/162",
	"https://github.com/dotnet/announcements/issues/51",
	"https://github.com/aspnet/Announcements/issues/352",
	"https://github.com/dotnet/announcements/issues/156",
	"https://github.com/aspnet/Announcements/issues/239",
	"https://github.com/aspnet/Announcements/issues/294",
	"https://github.com/dotnet/announcements/issues/12",
}

func main() {
	client := github.NewClient(nil)

	issueLinks := make(map[string]struct{})
	for _, repo := range repos {
		issues, _, err := client.Issues.ListByRepo(context.Background(), repo.owner, repo.name, &github.IssueListByRepoOptions{
			Labels: []string{"security"},
			ListOptions: github.ListOptions{
				Page:    0,
				PerPage: 500,
			},
		})
		if err != nil {
			log.Fatalf("Could not fetch issues for %s/%s: %v", repo.owner, repo.name, err)
		}

		for _, issue := range issues {
			if !strings.HasPrefix(issue.GetTitle(), "Microsoft Security Advisory") {
				continue
			}
			link := strings.ReplaceAll(issue.GetURL(), "api.github.com/repos", "github.com")
			issueLinks[link] = struct{}{}
		}

		root := "cves"
		err = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if filepath.Ext(info.Name()) == ".yaml" {
				bytes, err := ioutil.ReadFile(filepath.Join(root, info.Name()))
				if err != nil {
					return err
				}
				ff := &types.FileFormat{}
				if err := yaml.Unmarshal(bytes, ff); err != nil {
					log.Fatalf("could not parse yaml file %s: %v", info.Name(), err)
				}
				delete(issueLinks, ff.Link)
			}
			return nil
		})
		if err != nil {
			log.Fatalf("error walking cve dir: %v", err)
		}
	}
	// Remove all known missing links. Why the links are missing should be next to their declaration
	for _, knownMissing := range knownMissingLinks {
		delete(issueLinks, knownMissing)
	}
	if len(issueLinks) > 0 {
		for link := range issueLinks {
			log.Printf("Unaccounted for issue: %v", link)
		}
		log.Fatalf("Failing with non 0 exit code")
	}
}
