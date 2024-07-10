package oauthtoken

import (
	"context"
	"fmt"
	"testing"

	"github.com/EngFlow/auth/internal/autherr"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

type mockKeyring struct {
	password     string
	getCallCount int
	setCallCount int

	getErr error
	setErr error
}

func (m *mockKeyring) Get(service string, user string) (string, error) {
	m.getCallCount++
	if m.password == "" {
		return "", keyring.ErrNotFound
	}
	return m.password, m.getErr
}

func (m *mockKeyring) Set(service string, user string, password string) error {
	m.setCallCount++
	m.password = password
	return m.setErr
}

func TestKeyringTokenRoundtrip(t *testing.T) {
	testCases := []struct {
		desc          string
		keyringGetErr error
		keyringSetErr error

		wantStoreErr string
		wantLoadErr  string
	}{
		{
			desc: "happy path",
		},
		{
			desc:          "keyring set failure",
			keyringSetErr: fmt.Errorf("welcome to the party, pal!"),
			wantStoreErr:  "welcome to the party, pal!",
		},
		{
			desc:          "keyring get failure",
			keyringGetErr: fmt.Errorf("I read about them in Time Magazine"),
			wantLoadErr:   "Time Magazine",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			ctx := context.Background()
			mockImpl := &mockKeyring{
				getErr: tc.keyringGetErr,
				setErr: tc.keyringSetErr,
			}
			oldKeyringGet, oldKeyringSet := keyringGet, keyringSet
			defer func() {
				keyringGet, keyringSet = oldKeyringGet, oldKeyringSet
			}()
			keyringGet, keyringSet = mockImpl.Get, mockImpl.Set

			testKeyring := &Keyring{
				username: "jmcclane",
			}
			cluster := "nakatomiplaza.cluster.engflow.com"
			token := &oauth2.Token{
				AccessToken: uuid.New().String(),
			}
			_, gotErr := testKeyring.Load(ctx, cluster)
			assert.Equal(t, 1, mockImpl.getCallCount)
			require.Equal(t, autherr.ReauthRequired(cluster), gotErr)

			gotErr = testKeyring.Store(ctx, cluster, token)
			assert.Equal(t, 1, mockImpl.setCallCount)
			if tc.wantStoreErr != "" {
				assert.ErrorContains(t, gotErr, tc.wantStoreErr)
				return
			}
			require.NoError(t, gotErr)

			gotToken, gotErr := testKeyring.Load(ctx, cluster)
			assert.Equal(t, 2, mockImpl.getCallCount)
			if tc.wantLoadErr != "" {
				assert.ErrorContains(t, gotErr, tc.wantLoadErr)
				return
			}
			require.NoError(t, gotErr)
			assert.Equal(t, gotToken, token)
		})
	}
}
