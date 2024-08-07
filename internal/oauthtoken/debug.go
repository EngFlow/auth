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

package oauthtoken

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/oauth2"
)

type DebugPrint struct{}

func (d *DebugPrint) Store(ctx context.Context, cluster string, token *oauth2.Token) error {
	fmt.Fprintf(os.Stderr, "Token for cluster %q: %#v\n", cluster, token)
	return nil
}

func (d *DebugPrint) Load(ctx context.Context, cluster string) (*oauth2.Token, error) {
	return nil, errors.New("debug-printing token store is not able to load tokens")
}
