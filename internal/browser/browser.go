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
)

type Opener interface {
	Open(*url.URL) error
}

type StderrPrint struct{}

func (p *StderrPrint) Open(u *url.URL) error {
	fmt.Fprintf(
		os.Stderr,
		"Please open the following URL in your web browser to authenticate:\n\n\t%s\n\n",
		u,
	)
	return nil
}
