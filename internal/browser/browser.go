// Copyright 2024 EngFlow Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package browser

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
)

type Opener interface {
	Open(*url.URL) error
}

type StderrPrint struct{}

func openURL(url string) error {
	switch runtime.GOOS {
	case "darwin": // macOS
		return exec.Command("open", url).Run()
	case "linux":
		providers := []string{"xdg-open", "x-www-browser", "www-browser"}

		// There are multiple possible providers to open a browser on linux
		// One of them is xdg-open, another is x-www-browser, then there's www-browser, etc.
		// Look for one that exists and run it
		for _, provider := range providers {
			if binPath, err := exec.LookPath(provider); err == nil {
				err = exec.Command(binPath, url).Run()
				if err == nil {
					return nil
				}
			}
		}
		return fmt.Errorf("unsupported platform")
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Run()
	default:
		return fmt.Errorf("unsupported platform")
	}
}

func (p *StderrPrint) Open(u *url.URL) error {
	fmt.Fprintf(
		os.Stderr,
		`Attempting to automaticaly open the authentication URL in your web browser.
If the browser does not open or you wish to use a different device to authorize this request, open the following URL:
		%s`,
		u,
	)
	_ = openURL(u.String())
	return nil
}
