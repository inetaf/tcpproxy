// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

var (
	user          = flag.String("user", "", "username")
	repo          = flag.String("repo", "", "repository name")
	pkgType       = flag.String("pkg-type", "deb", "Package type, e.g. 'deb'")
	distro        = flag.String("distro", "", "distro name, e.g. 'debian'")
	distroVersion = flag.String("version", "", "distro version, e.g. 'stretch'")
	pkg           = flag.String("package", "", "package name")
	arch          = flag.String("arch", "", "package architecture")
	limit         = flag.Int("limit", 2, "package versions to keep")
)

func fatalf(msg string, args ...interface{}) {
	fmt.Printf(msg+"\n", args...)
	os.Exit(1)
}

func main() {
	flag.Parse()
	if *user == "" {
		fatalf("missing -user")
	}
	if *repo == "" {
		fatalf("missing -repo")
	}
	if *pkgType == "" {
		fatalf("missing -pkg-type")
	}
	if *distro == "" {
		fatalf("missing -distro")
	}
	if *distroVersion == "" {
		fatalf("missing -version")
	}
	if *pkg == "" {
		fatalf("missing -package")
	}
	if *arch == "" {
		fatalf("missing -arch")
	}
	if *limit < 1 {
		fatalf("limit must be >= 1")
	}

	files, err := packageVersions(*user, *repo, *pkgType, *distro, *distroVersion, *pkg, *arch)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if len(files) <= *limit {
		fmt.Println("Below limit, no packages deleted")
		return
	}
	delete := files[:len(files)-*limit]
	keep := files[len(files)-*limit:]
	if err = deletePackages(delete); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Deleted:\n\n%s\n\nKept:\n\n%s\n", strings.Join(delete, "\n"), strings.Join(keep, "\n"))
}

type packageMeta struct {
	Created  time.Time `json:"created_at"`
	Filename string    `json:"filename"`
}

type metaSort []packageMeta

func (m metaSort) Len() int           { return len(m) }
func (m metaSort) Less(i, j int) bool { return m[i].Created.Before(m[j].Created) }
func (m metaSort) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }

func packageVersions(user, repo, typ, distro, version, pkgname, arch string) ([]string, error) {
	url := fmt.Sprintf("https://%s:@packagecloud.io/api/v1/repos/%s/%s/package/%s/%s/%s/%s/%s/versions.json", os.Getenv("PACKAGECLOUD_API_KEY"), user, repo, typ, distro, version, pkgname, arch)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("get versions.json: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		msg, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("get error message of versions.json get: %s", err)
		}
		return nil, fmt.Errorf("get versions.json: %s (%q)", resp.Status, string(msg))
	}

	var files []packageMeta
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil {
		return nil, fmt.Errorf("decode versions.json: %s", err)
	}

	// Newest first
	sort.Sort(metaSort(files))

	var ret []string
	for _, meta := range files {
		ret = append(ret, fmt.Sprintf("/api/v1/repos/%s/%s/%s/%s/%s", user, repo, distro, version, meta.Filename))
	}

	return ret, nil
}

func deletePackages(urls []string) error {
	for _, url := range urls {
		fullURL := fmt.Sprintf("https://%s:@packagecloud.io%s", os.Getenv("PACKAGECLOUD_API_KEY"), url)
		req, err := http.NewRequest("DELETE", fullURL, nil)
		if err != nil {
			return fmt.Errorf("build delete request for %s: %s", url, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("delete %s: %s", url, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("delete %s: %s", url, resp.Status)
		}
	}
	return nil
}
