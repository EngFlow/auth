package oauthtoken

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/oauth2"

	"github.com/EngFlow/auth/internal/autherr"
)

type File struct {
	path string
}

type FileContents struct {
	Tokens map[string]*oauth2.Token `json:"tokens"`
}

func NewFile(path string) (*File, error) {
	return &File{path: path}, nil
}

func (f *File) readContents() (*FileContents, error) {
	parsed := &FileContents{
		Tokens: map[string]*oauth2.Token{},
	}

	contents, err := os.ReadFile(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		return parsed, nil
	}
	if err != nil {
		return nil, fmt.Errorf("can't read token storage: %w", err)
	}

	if err := json.Unmarshal(contents, parsed); err != nil {
		return nil, fmt.Errorf("can't parse token storage: %w", err)
	}

	return parsed, nil
}

func (f *File) writeContents(m *FileContents) error {
	if err := createIfNotExist(f.path); err != nil {
		return err
	}
	fh, err := os.CreateTemp(filepath.Dir(f.path), filepath.Base(f.path)+".*")
	if err != nil {
		return fmt.Errorf("failed to open temp file for writing token map: %w", err)
	}
	defer os.Remove(fh.Name())
	defer fh.Close()

	if err := fh.Chmod(0600); err != nil {
		return fmt.Errorf("failed to fix permissions on token storage: %w", err)
	}

	if err := json.NewEncoder(fh).Encode(m); err != nil {
		return fmt.Errorf("failed to write new token storage state: %w", err)
	}
	if err := fh.Close(); err != nil {
		return err
	}

	if err := os.Rename(fh.Name(), f.path); err != nil {
		return fmt.Errorf("failed to update token storage state: %w", err)
	}
	return nil
}

func (f *File) Load(ctx context.Context, cluster string) (*oauth2.Token, error) {
	authInfo, err := f.readContents()
	if err != nil {
		return nil, err
	}

	token, ok := authInfo.Tokens[cluster]
	if !ok {
		return nil, autherr.ReauthRequired(cluster)
	}
	return token, nil
}

func (f *File) Store(ctx context.Context, cluster string, token *oauth2.Token) error {
	authInfo, err := f.readContents()
	if err != nil {
		return err
	}

	authInfo.Tokens[cluster] = token

	if err := f.writeContents(authInfo); err != nil {
		return err
	}

	return nil
}

func createIfNotExist(path string) error {
	// Check that parent already exists
	if err := os.MkdirAll(filepath.Dir(path), 0777); err != nil {
		return fmt.Errorf("could not create config dir: %w", err)
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
			return fmt.Errorf("failed to initialize empty token storage: %w", err)
		}
		return nil
	} else if err != nil {
		return err
	}
	if info.IsDir() {
		return fmt.Errorf("path %q already exists as a directory", path)
	}
	return nil
}
