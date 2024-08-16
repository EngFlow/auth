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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"slices"
)

const (
	// configDir is the directory within os.UserConfigDir where this app
	// may store configuration files.
	configDir = "engflow_auth"

	// configName is the name of this app's configuration file.
	configName = configDir + "/config.json"

	// fileStoreDirName is the name of a directory where this app stores
	// unencrypted tokens.
	fileStoreDirName = configDir + "/tokens"
)

// config is the root struct holding the app's persistent configuration.
// It may be loaded and stored from a file in the user's configuration
// directory.
//
// This file may be read and written by different versions of engflow_auth,
// so avoid making incompatible changes. This file is always unencrypted,
// so don't store secrets here.
type config struct {
	Tokens []tokenConfig `json:"tokens"`
}

func (c *config) findTokenConfig(cluster string) (tokenConfig, bool) {
	for _, tok := range c.Tokens {
		if tok.Cluster == cluster {
			return tok, true
		}
	}
	return tokenConfig{}, false
}

func (c *config) deleteTokenConfig(cluster string) (deleted bool) {
	n := len(c.Tokens)
	c.Tokens = slices.DeleteFunc(c.Tokens, func(t tokenConfig) bool {
		return t.Cluster == cluster
	})
	return len(c.Tokens) != n
}

func (c *config) setTokenConfig(token tokenConfig) {
	for i, old := range c.Tokens {
		if old.Cluster == token.Cluster {
			c.Tokens[i] = token
			return
		}
	}
	c.Tokens = append(c.Tokens, token)
}

type tokenConfig struct {
	Cluster string `json:"cluster"`
	Store   string `json:"store"`
}

const (
	keyringStoreName string = "keyring"
	fileStoreName    string = "file"
)

func readConfigFile(path string) (config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return config{}, nil
	} else if err != nil {
		return config{}, fmt.Errorf("reading configuration file: %w", err)
	}
	var cfg config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return config{}, fmt.Errorf("parsing configuration file %s: %w", path, err)
	}
	return cfg, nil
}

func writeConfigFile(path string, cfg config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("formatting configuration file: %w", err)
	}
	if err := os.WriteFile(path, data, 0666); err != nil {
		return fmt.Errorf("writing configuration file: %w", err)
	}
	return nil
}
