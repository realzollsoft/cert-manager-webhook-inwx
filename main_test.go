package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	logf "github.com/cert-manager/cert-manager/pkg/logs"
	dns "github.com/cert-manager/cert-manager/test/acme"
	"github.com/cert-manager/cert-manager/test/acme/server"
	"github.com/go-logr/logr"
	"github.com/realzollsoft/cert-manager-webhook-inwx/test"
	"go.yaml.in/yaml/v3"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// testConfig represents the test configuration structure
type testConfig struct {
	Username             string       `json:"username"`
	Password             string       `json:"password"`
	OTPKey               string       `json:"otpKey"`
	UsernameSecretKeyRef SecretKeyRef `json:"usernameSecretKeyRef"`
	PasswordSecretKeyRef SecretKeyRef `json:"passwordSecretKeyRef"`
	OTPKeySecretKeyRef   SecretKeyRef `json:"otpKeySecretKeyRef"`
	TTL                  int          `json:"ttl,omitempty"`
	Sandbox              bool         `json:"sandbox,omitempty"`
}
type SecretKeyRef struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type testK8SSecret struct {
	APIVersion string                `yaml:"apiVersion,omitempty"`
	Kind       string                `yaml:",omitempty"`
	Metadata   TestK8SSecretMetadata `yaml:"metadata"`
	Data       TestK8SSecretData     `yaml:"data,omitempty"`
}
type TestK8SSecretMetadata struct {
	Name string `yaml:"name,omitempty"`
}
type TestK8SSecretData struct {
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	OTPKey   string `yaml:"otpKey,omitempty"`
}

var (
	zone      = "zollsoft.de."
	zoneTwoFA = "zollsoftmfa.de."
	fqdn      string
	l         logr.Logger
)

func init() {
	cfg := textlogger.NewConfig(textlogger.Verbosity(3))
	l = textlogger.NewLogger(cfg).WithName("certmanager-inwx-test")
	log.SetLogger(l)
}

func checkTestBasicPreconditions(t *testing.T) {
	// Skip API integration tests if running with dummy credentials
	if os.Getenv("INWX_USER") == "" || os.Getenv("INWX_USER") == "test-user" {
		t.Skip("Skipping API integration tests - no real INWX credentials provided")
	}
}
func checkTest2FAPreconditions(t *testing.T) {
	// Skip API integration tests if running with dummy credentials
	if os.Getenv("INWX_USER_OTP") == "" || os.Getenv("INWX_USER_OTP") == "test-user-otp" {
		t.Skip("Skipping API integration tests - no real INWX OTP credentials provided")
	}
}

func TestRunSuite(t *testing.T) {
	checkTestBasicPreconditions(t)
	if os.Getenv("TEST_ZONE_NAME") != "" {
		zone = os.Getenv("TEST_ZONE_NAME")
	}
	fqdn = "cert-manager-dns01-tests." + zone

	srv, ctx := createBasicServerAndCtx(t, "dnsBasicServe", zone)
	if err := srv.Run(ctx, "udp"); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer srv.Shutdown()

	configData := testConfig{
		Username: os.Getenv("INWX_USER"),
		Password: os.Getenv("INWX_PASSWORD"),
	}

	configJSON := jsonBytesWithSandboxAndTTL300(t, &configData)

	fixture := dns.NewFixture(&solver{},
		dns.SetResolvedZone(zone),
		dns.SetResolvedFQDN(fqdn),
		dns.SetAllowAmbientCredentials(false),
		dns.SetDNSServer(srv.ListenAddr()),
		dns.SetPropagationLimit(time.Duration(60)*time.Second),
		dns.SetUseAuthoritative(false),
		// Set to false because INWX implementation deletes all records
		dns.SetStrict(false),
		dns.SetConfig(&extapi.JSON{
			Raw: configJSON,
		}),
	)

	fixture.RunConformance(t)
}

func TestRunSuiteWithSecret(t *testing.T) {
	checkTestBasicPreconditions(t)

	if os.Getenv("TEST_ZONE_NAME") != "" {
		zone = os.Getenv("TEST_ZONE_NAME")
	}
	fqdn = "cert-manager-dns01-tests-with-secret." + zone

	srv, ctx := createBasicServerAndCtx(t, "dnsBasicServerSecret", zone)
	if err := srv.Run(ctx, "udp"); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer srv.Shutdown()

	configData := testConfig{
		UsernameSecretKeyRef: SecretKeyRef{
			Name: "inwx-credentials",
			Key:  "username",
		},
		PasswordSecretKeyRef: SecretKeyRef{
			Name: "inwx-credentials",
			Key:  "password",
		},
	}

	configJSON := jsonBytesWithSandboxAndTTL300(t, &configData)
	sec := newTestK8SSecretUserPass()
	fd, fp, err := writeSecretConfigToDir(t, "inwx-secret.yaml", sec)
	defer deleteFile(t, fp)
	if err != nil {
		t.Logf("Could not write secret config: %v", err)
		t.FailNow()
	}

	fixture := dns.NewFixture(&solver{},
		dns.SetResolvedZone(zone),
		dns.SetResolvedFQDN(fqdn),
		dns.SetAllowAmbientCredentials(false),
		dns.SetDNSServer(srv.ListenAddr()),
		dns.SetManifestPath(fd),
		dns.SetPropagationLimit(time.Duration(60)*time.Second),
		dns.SetUseAuthoritative(false),
		dns.SetConfig(&extapi.JSON{
			Raw: configJSON,
		}),
	)

	fixture.RunConformance(t)
}

func TestRunSuiteWithTwoFA(t *testing.T) {
	checkTest2FAPreconditions(t)

	if os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA") != "" {
		zoneTwoFA = os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA")
	}

	fqdn = "cert-manager-dns01-tests." + zoneTwoFA

	srv, ctx := createBasicServerAndCtx(t, "dnsBasicServer", zoneTwoFA)
	if err := srv.Run(ctx, "udp"); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer srv.Shutdown()
	configData := testConfig{
		Username: os.Getenv("INWX_USER_OTP"),
		Password: os.Getenv("INWX_PASSWORD_OTP"),
		OTPKey:   os.Getenv("INWX_OTPKEY"),
	}
	configJSON := jsonBytesWithSandboxAndTTL300(t, &configData)

	fixture := dns.NewFixture(&solver{},
		dns.SetResolvedZone(zoneTwoFA),
		dns.SetResolvedFQDN(fqdn),
		dns.SetAllowAmbientCredentials(false),
		dns.SetDNSServer(srv.ListenAddr()),
		dns.SetPropagationLimit(time.Duration(60)*time.Second),
		dns.SetUseAuthoritative(false),
		// Set to false because INWX implementation deletes all records
		dns.SetStrict(false),
		dns.SetConfig(&extapi.JSON{
			Raw: configJSON,
		}),
	)

	fixture.RunConformance(t)
}

func TestRunSuiteWithSecretAndTwoFA(t *testing.T) {
	checkTest2FAPreconditions(t)

	if os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA") != "" {
		zoneTwoFA = os.Getenv("TEST_ZONE_NAME_WITH_TWO_FA")
	}
	fqdn = "cert-manager-dns01-tests-with-secret." + zoneTwoFA

	srv, ctx := createBasicServerAndCtx(t, "dnsBasicServerSecret", zoneTwoFA)

	if err := srv.Run(ctx, "udp"); err != nil {
		t.Fatalf("failed to start test server: %v", err)
	}
	defer srv.Shutdown()
	configData := testConfig{
		UsernameSecretKeyRef: SecretKeyRef{
			Name: "inwx-credentials",
			Key:  "username",
		},
		PasswordSecretKeyRef: SecretKeyRef{
			Name: "inwx-credentials",
			Key:  "password",
		},
		OTPKeySecretKeyRef: SecretKeyRef{
			Name: "inwx-credentials",
			Key:  "otpKey",
		},
	}

	configJSON := jsonBytesWithSandboxAndTTL300(t, &configData)
	sec := newTestK8SSecretWith2FA()
	fd, fp, err := writeSecretConfigToDir(t, "inwx-otp-secret.yaml", sec)
	defer deleteFile(t, fp)
	if err != nil {
		t.Logf("Could not write secret config: %v", err)
		t.FailNow()
	}
	fixture := dns.NewFixture(&solver{},
		dns.SetResolvedZone(zoneTwoFA),
		dns.SetResolvedFQDN(fqdn),
		dns.SetAllowAmbientCredentials(false),
		dns.SetDNSServer(srv.ListenAddr()),
		dns.SetManifestPath(fd),
		dns.SetPropagationLimit(time.Duration(60)*time.Second),
		dns.SetUseAuthoritative(false),
		dns.SetConfig(&extapi.JSON{
			Raw: configJSON,
		}),
	)

	fixture.RunConformance(t)
}

func createBasicServerAndCtx(t *testing.T, name string, zoneStr string) (*server.BasicServer, context.Context) {
	ctx := logf.NewContext(context.TODO(), l, t.Name())
	srv := &server.BasicServer{
		Handler: &test.Handler{
			Log: logf.FromContext(ctx, name),
			TxtRecords: map[string][][]string{
				fqdn: {
					{},
					{},
					{"123d=="},
					{"123d=="},
				},
			},
			Zones: []string{zoneStr},
		},
	}
	return srv, ctx
}

// jsonBytesWithSandboxAndTTL300 sets "sandbox" in config to "true" and a TTL of 300
// returns the json-representation of the config as byte-slice
func jsonBytesWithSandboxAndTTL300(t *testing.T, cfg *testConfig) []byte {
	cfg.Sandbox = true
	cfg.TTL = 300
	configJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}
	return configJSON
}

func writeSecretConfigToDir(t *testing.T, fName string, v testK8SSecret) (string, string, error) {
	testDir := t.TempDir()
	fullPath := filepath.Join(testDir, fName)
	data, err := yaml.Marshal(v)
	if err != nil {
		return "", "", err
	}
	return testDir, fullPath, os.WriteFile(fullPath, data, 0777)
}
func deleteFile(t *testing.T, fPath string) {
	if fPath != "" && fPath != "/" {
		return
	}
	err := os.Remove(fPath)
	if err != nil {
		t.Logf("Couldn't delete file %v", fPath)
	}
}

func newTestK8SSecretUserPass() testK8SSecret {
	data := TestK8SSecretData{
		Username: envAsB64("INWX_USER"),
		Password: envAsB64("INWX_PASSWORD"),
	}
	return newTestK8SSecret(data)
}
func newTestK8SSecretWith2FA() testK8SSecret {
	data := TestK8SSecretData{
		Username: envAsB64("INWX_USER_OTP"),
		Password: envAsB64("INWX_PASSWORD_OTP"),
		OTPKey:   envAsB64("INWX_OTPKEY"),
	}
	return newTestK8SSecret(data)
}
func envAsB64(key string) string {
	val := os.Getenv(key)
	return base64.StdEncoding.EncodeToString([]byte(val))
}
func newTestK8SSecret(data TestK8SSecretData) testK8SSecret {
	return testK8SSecret{
		APIVersion: "v1",
		Kind:       "Secret",
		Metadata: TestK8SSecretMetadata{
			Name: "inwx-credentials",
		},
		Data: data,
	}
}
