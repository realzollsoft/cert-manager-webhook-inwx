package solver

import (
	"encoding/json"
	"testing"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/nrdcg/goinwx"
	"github.com/realzollsoft/cert-manager-webhook-inwx/internal/solver/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	clienttest "k8s.io/client-go/testing"
)

// TestConfigLoading tests configuration parsing and validation
func TestConfigLoading(t *testing.T) {
	tests := []struct {
		name            string
		configJSON      []byte
		expectedTTL     int
		expectedSandbox bool
		errAssertion    assert.ErrorAssertionFunc
	}{
		{
			name:            "default config",
			configJSON:      []byte(`{}`),
			expectedTTL:     300,
			expectedSandbox: false,
			errAssertion:    assert.NoError,
		},
		{
			name:            "nil config",
			configJSON:      nil,
			expectedTTL:     300,
			expectedSandbox: false,
			errAssertion:    assert.NoError,
		},
		{
			name:            "custom TTL",
			configJSON:      []byte(`{"ttl": 600}`),
			expectedTTL:     600,
			expectedSandbox: false,
			errAssertion:    assert.NoError,
		},
		{
			name:            "TTL too low should use default",
			configJSON:      []byte(`{"ttl": 100}`),
			expectedTTL:     300, // Should use default
			expectedSandbox: false,
			errAssertion:    assert.NoError,
		},
		{
			name:            "sandbox mode enabled",
			configJSON:      []byte(`{"sandbox": true}`),
			expectedTTL:     300,
			expectedSandbox: true,
			errAssertion:    assert.NoError,
		},
		{
			name:         "invalid JSON",
			configJSON:   []byte(`{invalid json}`),
			errAssertion: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := loadConfig(tt.configJSON)

			tt.errAssertion(t, err)
			assert.Equal(t, config.TTL, tt.expectedTTL)
			assert.Equal(t, tt.expectedSandbox, config.Sandbox)
		})
	}
}

// TestCredentialsValidation tests credential validation logic
func TestGetCredentials(t *testing.T) {
	tests := []struct {
		name      string
		cfg       Config
		expCred   *Credentials
		errAssert assert.ErrorAssertionFunc
	}{
		{
			name: "valid credentials in plaintext config",
			cfg: Config{
				Username: "testuser",
				Password: "testpass",
				OTPKey:   "testkey",
			},
			expCred: &Credentials{
				Username: "testuser",
				Password: "testpass",
				OTPKey:   "testkey",
			},
			errAssert: assert.NoError,
		},
		{
			name: "missing username",
			cfg: Config{
				Password: "testpass",
			},
			errAssert: assert.Error,
		},
		{
			name: "missing password",
			cfg: Config{
				Username: "testuser",
			},
			errAssert: assert.Error,
		},
		{
			name:      "empty config",
			cfg:       Config{},
			errAssert: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td := createSolverTestData(t)
			ns := "test"
			td.k8sClient.PrependReactor("*", "*", func(action clienttest.Action) (handled bool, ret runtime.Object, err error) {
				return false, nil, nil // don't yield any results here (we want to test "plain" configuration)
			})

			res, err := td.s.getCredentials(&tt.cfg, ns)
			tt.errAssert(t, err)
			assert.Equal(t, tt.expCred, res)
		})
	}
}

// TestGetCredentialsWithSecrets tests credential logic with secrets
func TestGetCredentialsWithSecrets(t *testing.T) {
	tests := []struct {
		name         string
		cfg          Config
		expCred      *Credentials
		clientSecret *corev1.Secret
		clientErr    error
		inStringData bool
		errAssert    assert.ErrorAssertionFunc
	}{
		{
			name: "valid credentials in stringdata of secret",
			cfg: Config{
				UsernameSecretKeyRef: v1.SecretKeySelector{Key: "certusername"},
				PasswordSecretKeyRef: v1.SecretKeySelector{Key: "certpass"},
				OTPKeySecretKeyRef:   v1.SecretKeySelector{Key: "certotp"},
			},
			clientSecret: &corev1.Secret{
				StringData: map[string]string{
					"certusername": "testuser",
					"certpass":     "testpass",
					"certotp":      "testotp",
				},
			},
			inStringData: true,
			expCred: &Credentials{
				Username: "testuser",
				Password: "testpass",
				OTPKey:   "testotp",
			},
			errAssert: assert.NoError,
		},
		{
			name: "valid credentials in data of secret",
			cfg: Config{
				UsernameSecretKeyRef: v1.SecretKeySelector{Key: "certusername"},
				PasswordSecretKeyRef: v1.SecretKeySelector{Key: "certpass"},
				OTPKeySecretKeyRef:   v1.SecretKeySelector{Key: "certotp"},
			},
			clientSecret: &corev1.Secret{
				Data: map[string][]byte{
					"certusername": []byte("testuser"),
					"certpass":     []byte("testpass"),
					"certotp":      []byte("testotp"),
				},
			},
			expCred: &Credentials{
				Username: "testuser",
				Password: "testpass",
				OTPKey:   "testotp",
			},
			errAssert: assert.NoError,
		},
		{
			name: "no credentials in data of secret",
			cfg: Config{
				UsernameSecretKeyRef: v1.SecretKeySelector{Key: "certusername"},
				PasswordSecretKeyRef: v1.SecretKeySelector{Key: "certpass"},
				OTPKeySecretKeyRef:   v1.SecretKeySelector{Key: "certotp"},
			},
			clientSecret: &corev1.Secret{
				Data: map[string][]byte{},
			},
			expCred:   nil,
			errAssert: assert.Error,
		},
		{
			name: "missing password credentials in data of secret",
			cfg: Config{
				UsernameSecretKeyRef: v1.SecretKeySelector{Key: "certusername"},
				PasswordSecretKeyRef: v1.SecretKeySelector{Key: "certpass"},
				OTPKeySecretKeyRef:   v1.SecretKeySelector{Key: "certotp"},
			},
			clientSecret: &corev1.Secret{
				Data: map[string][]byte{
					"certusername": []byte("testuser"),
					"certotp":      []byte("testotp"),
				},
			},
			expCred:   nil,
			errAssert: assert.Error,
		},
		{
			name: "missing otp key credential in data of secret",
			cfg: Config{
				UsernameSecretKeyRef: v1.SecretKeySelector{Key: "certusername"},
				PasswordSecretKeyRef: v1.SecretKeySelector{Key: "certpass"},
				OTPKeySecretKeyRef:   v1.SecretKeySelector{Key: "certotp"},
			},
			clientSecret: &corev1.Secret{
				Data: map[string][]byte{
					"certusername": []byte("testuser"),
					"certpass":     []byte("testpass"),
				},
			},
			expCred:   nil,
			errAssert: assert.Error,
		},
		{
			name: "error from client",
			cfg: Config{
				UsernameSecretKeyRef: v1.SecretKeySelector{Key: "certusername"},
				PasswordSecretKeyRef: v1.SecretKeySelector{Key: "certpass"},
				OTPKeySecretKeyRef:   v1.SecretKeySelector{Key: "certotp"},
			},
			clientErr: assert.AnError,
			expCred:   nil,
			errAssert: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			td := createSolverTestData(t)
			ns := "test"
			td.k8sClient.PrependReactor("get", "secrets", func(action clienttest.Action) (handled bool, ret runtime.Object, err error) {
				return true, tt.clientSecret, tt.clientErr
			})

			res, err := td.s.getCredentials(&tt.cfg, ns)
			tt.errAssert(t, err)
			assert.Equal(t, tt.expCred, res)
		})
	}
}

func TestSolverNewClientFromChallenge(t *testing.T) {
	createTestChallenge := func() *v1alpha1.ChallengeRequest {
		return &v1alpha1.ChallengeRequest{
			ResolvedZone:      "sub.example.com.",
			ResolvedFQDN:      "_acme-challenge.sub.example.com.",
			Key:               "test-key",
			ResourceNamespace: "test-namespace",
		}
	}
	noOpReaction := func(action clienttest.Action) (handled bool, ret runtime.Object, err error) {
		return false, nil, nil // don't yield any results
	}
	t.Run("success", func(t *testing.T) {
		td := createSolverTestData(t)
		chal := createTestChallenge()
		cfg := createDummyConfig()
		chal.Config = &extapi.JSON{Raw: asJSON(t, cfg)}
		td.k8sClient.PrependReactor("*", "*", noOpReaction)
		td.inwxClient.EXPECT().Login().Return(nil)

		cl, rcfg, err := td.s.newClientFromChallenge(chal)

		assert.NoError(t, err)
		assert.NotEmpty(t, *cfg, *rcfg)
		assert.NotNil(t, cl)
	})
	t.Run("Config error", func(t *testing.T) {
		td := createSolverTestData(t)
		chal := createTestChallenge()
		chal.Config = &extapi.JSON{Raw: []byte(`{invalid json}`)}
		cl, cfg, err := td.s.newClientFromChallenge(chal)
		assert.Error(t, err)
		assert.Empty(t, cfg)
		assert.Nil(t, cl)
	})
	t.Run("error getting credentials", func(t *testing.T) {
		td := createSolverTestData(t)
		chal := createTestChallenge()
		cfg := createDummyConfig()
		// set empty password
		cfg.Password = ""
		cfg.PasswordSecretKeyRef = v1.SecretKeySelector{}
		chal.Config = &extapi.JSON{Raw: asJSON(t, cfg)}
		td.k8sClient.PrependReactor("*", "*", noOpReaction)

		cl, rcfg, err := td.s.newClientFromChallenge(chal)

		assert.ErrorContains(t, err, "getting credentials")
		assert.NotEmpty(t, *cfg, *rcfg)
		assert.Nil(t, cl)
	})
	t.Run("login error", func(t *testing.T) {
		td := createSolverTestData(t)
		chal := createTestChallenge()
		cfg := createDummyConfig()
		chal.Config = &extapi.JSON{Raw: asJSON(t, cfg)}
		td.k8sClient.PrependReactor("*", "*", noOpReaction)
		td.inwxClient.EXPECT().Login().Return(assert.AnError)

		cl, rcfg, err := td.s.newClientFromChallenge(chal)

		assert.Error(t, err)
		assert.NotEmpty(t, *cfg, *rcfg)
		assert.Nil(t, cl)
	})
	t.Run("error unlock with otp key", func(t *testing.T) {
		td := createSolverTestData(t)
		chal := createTestChallenge()
		cfg := createDummyConfig()
		cfg.OTPKey = "mykey"
		chal.Config = &extapi.JSON{Raw: asJSON(t, cfg)}
		td.k8sClient.PrependReactor("*", "*", noOpReaction)
		td.inwxClient.EXPECT().Login().Return(nil)
		td.inwxClient.EXPECT().TryToUnlockWithOTPKey(cfg.OTPKey, true).Return(assert.AnError, assert.AnError)

		cl, rcfg, err := td.s.newClientFromChallenge(chal)

		assert.Error(t, err)
		assert.NotEmpty(t, *cfg, *rcfg)
		assert.Nil(t, cl)
	})

}

func TestSolverPresent(t *testing.T) {
	challenge := &v1alpha1.ChallengeRequest{
		ResolvedZone:      "sub.example.com.",
		ResolvedFQDN:      "_acme-challenge.sub.example.com.",
		Key:               "test-key",
		ResourceNamespace: "test-namespace",
	}
	expRequest := &goinwx.NameserverRecordRequest{
		Domain:  "sub.example.com",
		Name:    "_acme-challenge",
		Type:    "TXT",
		Content: "test-key",
		TTL:     defaultConfig.TTL,
	}
	cfg := createDummyConfig()
	cfgBytes := asJSON(t, cfg)
	td := createSolverTestData(t)
	challenge.Config = &extapi.JSON{Raw: cfgBytes}

	td.inwxClient.EXPECT().Login().Return(nil)
	td.inwxClient.EXPECT().NameserverCreateRecord(expRequest).Return("something", nil)
	td.inwxClient.EXPECT().Logout()

	err := td.s.Present(challenge)
	assert.NoError(t, err)
}

func TestSolverPresentWithErrorOnLogin(t *testing.T) {
	challenge := &v1alpha1.ChallengeRequest{
		ResolvedZone:      "example.com.",
		ResolvedFQDN:      "_acme-challenge.example.com.",
		Key:               "test-key",
		ResourceNamespace: "test-namespace",
	}
	cfg := createDummyConfig()
	cfgBytes := asJSON(t, cfg)
	td := createSolverTestData(t)
	challenge.Config = &extapi.JSON{Raw: cfgBytes}

	td.inwxClient.EXPECT().Login().Return(assert.AnError)

	err := td.s.Present(challenge)
	assert.Error(t, err)
}

func TestSolverPresentWithErrorOnCreateRecord(t *testing.T) {
	tests := []struct {
		name      string
		errResp   error
		errAssert assert.ErrorAssertionFunc
	}{
		{
			name:      "general error",
			errResp:   assert.AnError,
			errAssert: assert.Error,
		},
		{
			name: "general error from inwx",
			errResp: &goinwx.ErrorResponse{
				Message: "Some error",
			},
			errAssert: assert.Error,
		},
		{
			name: "object exists error from inwx",
			errResp: &goinwx.ErrorResponse{
				Message: "Object exists",
			},
			errAssert: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge := &v1alpha1.ChallengeRequest{
				ResolvedZone:      "example.com.",
				ResolvedFQDN:      "_acme-challenge.example.com.",
				Key:               "test-key",
				ResourceNamespace: "test-namespace",
			}
			expRequest := &goinwx.NameserverRecordRequest{
				Domain:  "example.com",
				Name:    "_acme-challenge",
				Type:    "TXT",
				Content: "test-key",
				TTL:     defaultConfig.TTL,
			}
			cfg := createDummyConfig()
			cfgBytes := asJSON(t, cfg)
			td := createSolverTestData(t)
			challenge.Config = &extapi.JSON{Raw: cfgBytes}

			td.inwxClient.EXPECT().Login().Return(nil)
			td.inwxClient.EXPECT().NameserverCreateRecord(expRequest).Return("", tt.errResp)
			td.inwxClient.EXPECT().Logout()

			err := td.s.Present(challenge)
			tt.errAssert(t, err)
		})
	}
}

func TestSolverCleanup(t *testing.T) {
	challenge := &v1alpha1.ChallengeRequest{
		ResolvedZone:      "sub.example.com.",
		ResolvedFQDN:      "_acme-challenge.sub.example.com.",
		Key:               "test-key",
		ResourceNamespace: "test-namespace",
	}
	mockResp := &goinwx.NameserverInfoResponse{
		Records: []goinwx.NameserverRecord{
			{
				ID:   "1",
				Name: "_acme-challenge",
				Type: "TXT",
			},
			{
				ID:   "2",
				Name: "_acme-challenge2",
				Type: "TXT",
			},
		},
	}
	expRequest := &goinwx.NameserverInfoRequest{
		Domain: "sub.example.com",
		Name:   "_acme-challenge",
		Type:   "TXT",
	}
	cfg := createDummyConfig()
	cfgBytes := asJSON(t, cfg)
	td := createSolverTestData(t)
	challenge.Config = &extapi.JSON{Raw: cfgBytes}

	td.inwxClient.EXPECT().Login().Return(nil)
	td.inwxClient.EXPECT().NameserverInfo(expRequest).Return(mockResp, nil)
	td.inwxClient.EXPECT().NameserverDeleteRecord("1").Return(nil)
	td.inwxClient.EXPECT().NameserverDeleteRecord("2").Return(nil)
	td.inwxClient.EXPECT().Logout()

	err := td.s.CleanUp(challenge)
	assert.NoError(t, err)
}

func TestSolverCleanupWithLoginError(t *testing.T) {
	challenge := &v1alpha1.ChallengeRequest{
		ResolvedZone:      "sub.example.com.",
		ResolvedFQDN:      "_acme-challenge.sub.example.com.",
		Key:               "test-key",
		ResourceNamespace: "test-namespace",
	}
	cfg := createDummyConfig()
	cfgBytes := asJSON(t, cfg)
	td := createSolverTestData(t)
	challenge.Config = &extapi.JSON{Raw: cfgBytes}

	td.inwxClient.EXPECT().Login().Return(assert.AnError)

	err := td.s.CleanUp(challenge)
	assert.Error(t, err)
}

func TestSolverCleanupWithInfoError(t *testing.T) {
	challenge := &v1alpha1.ChallengeRequest{
		ResolvedZone:      "sub.example.com.",
		ResolvedFQDN:      "_acme-challenge.sub.example.com.",
		Key:               "test-key",
		ResourceNamespace: "test-namespace",
	}
	expRequest := &goinwx.NameserverInfoRequest{
		Domain: "sub.example.com",
		Name:   "_acme-challenge",
		Type:   "TXT",
	}
	cfg := createDummyConfig()
	cfgBytes := asJSON(t, cfg)
	td := createSolverTestData(t)
	challenge.Config = &extapi.JSON{Raw: cfgBytes}

	td.inwxClient.EXPECT().Login().Return(nil)
	td.inwxClient.EXPECT().NameserverInfo(expRequest).Return(nil, assert.AnError)
	td.inwxClient.EXPECT().Logout()

	err := td.s.CleanUp(challenge)
	assert.Error(t, err)
}

func TestSolverCleanupWithErrorOnDelete(t *testing.T) {
	challenge := &v1alpha1.ChallengeRequest{
		ResolvedZone:      "sub.example.com.",
		ResolvedFQDN:      "_acme-challenge.sub.example.com.",
		Key:               "test-key",
		ResourceNamespace: "test-namespace",
	}
	mockResp := &goinwx.NameserverInfoResponse{
		Records: []goinwx.NameserverRecord{
			{
				ID:   "1",
				Name: "_acme-challenge",
				Type: "TXT",
			},
			{
				ID:   "2",
				Name: "_acme-challenge2",
				Type: "TXT",
			},
		},
	}
	expRequest := &goinwx.NameserverInfoRequest{
		Domain: "sub.example.com",
		Name:   "_acme-challenge",
		Type:   "TXT",
	}
	cfg := createDummyConfig()
	cfgBytes := asJSON(t, cfg)
	td := createSolverTestData(t)
	challenge.Config = &extapi.JSON{Raw: cfgBytes}

	td.inwxClient.EXPECT().Login().Return(nil)
	td.inwxClient.EXPECT().NameserverInfo(expRequest).Return(mockResp, nil)
	td.inwxClient.EXPECT().NameserverDeleteRecord("1").Return(assert.AnError)
	td.inwxClient.EXPECT().NameserverDeleteRecord("2").Return(nil)
	td.inwxClient.EXPECT().Logout()

	err := td.s.CleanUp(challenge)
	assert.Error(t, err)
}

func TestInitialize(t *testing.T) {
	fakeClient := fake.NewClientset()
	mockClientBuilder := func(c *rest.Config) (kubernetes.Interface, error) {
		return fakeClient, nil
	}
	s := &solver{
		buildK8sClient: mockClientBuilder,
	}
	rcfg := &rest.Config{Host: "localhost"}
	require.Nil(t, s.k8sCl)

	err := s.Initialize(rcfg, nil)

	assert.NoError(t, err)
	assert.NotNil(t, s.k8sCl)
}
func TestInitializeWithError(t *testing.T) {
	mockClientBuilder := func(c *rest.Config) (kubernetes.Interface, error) {
		return nil, assert.AnError
	}
	s := &solver{
		buildK8sClient: mockClientBuilder,
	}
	rcfg := &rest.Config{Host: "localhost"}
	require.Nil(t, s.k8sCl)

	err := s.Initialize(rcfg, nil)

	assert.Error(t, err)
	assert.Nil(t, s.k8sCl)
}

func TestSolverName(t *testing.T) {
	td := createSolverTestData(t)
	res := td.s.Name()
	assert.Equal(t, "inwx", res)
}

type solverTestData struct {
	s          *solver
	k8sClient  *fake.Clientset
	inwxClient *mocks.INWXClient
}

func createSolverTestData(t *testing.T) *solverTestData {
	inwxClient := mocks.NewINWXClient(t)
	fakeClient := fake.NewClientset()
	mockClientBuilder := func(c *rest.Config) (kubernetes.Interface, error) {
		return fakeClient, nil
	}
	mockINWXClientBuilder := func(cfg *Config, creds *Credentials) INWXClient {
		return inwxClient
	}
	s := &solver{
		buildK8sClient:  mockClientBuilder,
		buildINWXClient: mockINWXClientBuilder,
		k8sCl:           fakeClient,
	}
	return &solverTestData{
		s:          s,
		k8sClient:  fakeClient,
		inwxClient: inwxClient,
	}
}

func createDummyConfig() *Config {
	return &Config{
		Username: "testuser",
		Password: "testpass",
	}
}

func asJSON(t *testing.T, in any) []byte {
	res, err := json.Marshal(in)
	if err != nil {
		assert.FailNow(t, "could not marshal json", err)
	}
	return res
}
