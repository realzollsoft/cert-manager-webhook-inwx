package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	dnst "github.com/cert-manager/cert-manager/test/acme"
	"github.com/cert-manager/cert-manager/test/acme/server"
	"github.com/miekg/dns"
	"github.com/nrdcg/goinwx"
	"github.com/realzollsoft/cert-manager-webhook-inwx/internal/solver"
	"github.com/realzollsoft/cert-manager-webhook-inwx/internal/solver/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2/textlogger"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/yaml"
)

const secretKeyRefName = "inwx-credentials"

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

const (
	envZone     = "TEST_ZONE_NAME"
	envZone2FA  = "TEST_ZONE_NAME_WITH_TWO_FA"
	dfltZone    = "zollsoft.de."
	dfltZone2FA = "zollsoftmfa.de."
)

func TestRunSuite(t *testing.T) {
	td := createComponentTestData(t, false)
	zone := envOrDefault(envZone, dfltZone)
	fqdn := "cert-manager-dns01-tests." + zone
	configJSON := td.directConfig(false)
	td.expectINWXUserPasswordCalls()
	td.expectDNSServerCalls(fqdn)

	// Set strict to false because INWX implementation deletes all records
	runConformanceTests(td, zone, fqdn, configJSON, dnst.SetStrict(false))
}

func TestRunSuiteWithSecret(t *testing.T) {
	td := createComponentTestData(t, false)
	zone := envOrDefault(envZone, dfltZone)
	fqdn := "cert-manager-dns01-tests-with-secret." + zone
	configJSON, fd := td.secretConfig(false)
	td.expectINWXUserPasswordCalls()
	td.expectDNSServerCalls(fqdn)

	runConformanceTests(td, zone, fqdn, configJSON, dnst.SetManifestPath(fd))
}

func TestRunSuiteWithTwoFA(t *testing.T) {
	td := createComponentTestData(t, true)
	zoneTwoFA := envOrDefault(envZone2FA, dfltZone2FA)
	fqdn := "cert-manager-dns01-tests." + zoneTwoFA
	configJSON := td.directConfig(true)
	td.expectINWXOTPCalls()
	td.expectDNSServerCalls(fqdn)

	// Set strict to false because INWX implementation deletes all records
	runConformanceTests(td, zoneTwoFA, fqdn, configJSON, dnst.SetStrict(false))
}

func TestRunSuiteWithSecretAndTwoFA(t *testing.T) {
	td := createComponentTestData(t, true)
	zoneTwoFA := envOrDefault(envZone2FA, dfltZone2FA)
	fqdn := "cert-manager-dns01-tests-with-secret." + zoneTwoFA
	configJSON, fd := td.secretConfig(true)
	td.expectINWXOTPCalls()
	td.expectDNSServerCalls(fqdn)

	runConformanceTests(td, zoneTwoFA, fqdn, configJSON, dnst.SetManifestPath(fd))
}

func runConformanceTests(td *componentTestData, zone string, fqdn string, configJSON []byte, opts ...dnst.Option) {
	cfg := textlogger.NewConfig(textlogger.Verbosity(3))
	l := textlogger.NewLogger(cfg).WithName("certmanager-inwx-test")
	log.SetLogger(l)
	ctx := logf.NewContext(context.TODO(), l, td.t.Name())
	srv := &server.BasicServer{Handler: td.dnsHandler}
	err := srv.Run(ctx, "udp")
	require.NoError(td.t, err, "failed to start test server: %v", err)
	defer srv.Shutdown()

	dnsCommonOpts := []dnst.Option{
		dnst.SetResolvedZone(zone),
		dnst.SetResolvedFQDN(fqdn),
		dnst.SetAllowAmbientCredentials(false),
		dnst.SetDNSServer(srv.ListenAddr()),
		dnst.SetPropagationLimit(time.Duration(60) * time.Second),
		dnst.SetUseAuthoritative(false),
		dnst.SetConfig(&extapi.JSON{Raw: configJSON}),
	}
	allOpts := append(dnsCommonOpts, opts...)
	fixture := dnst.NewFixture(td.solver, allOpts...)

	fixture.RunConformance(td.t)
}

func keyRef(key string) SecretKeyRef {
	return SecretKeyRef{Name: secretKeyRefName, Key: key}
}

// jsonBytesWithSandboxAndTTL300 sets "sandbox" in config to "true" and a TTL of 300
// returns the json-representation of the config as byte-slice
func jsonBytesWithSandboxAndTTL300(t *testing.T, cfg *testConfig) []byte {
	cfg.Sandbox = true
	cfg.TTL = 300
	configJSON, err := json.Marshal(cfg)
	require.NoError(t, err)
	return configJSON
}

func writeSecretConfigToDir(t *testing.T, fName string, v corev1.Secret) string {
	testDir := t.TempDir()
	fullPath := filepath.Join(testDir, fName)
	data, err := yaml.Marshal(v)
	require.NoError(t, err, "Couldn't write secret config")
	os.WriteFile(fullPath, data, 0777)
	require.NoError(t, err, "Couldn't write secret config")
	return testDir
}

func usernamePassCredentials() (string, string) {
	return os.Getenv("INWX_USER"), os.Getenv("INWX_PASSWORD")
}

func otpCredentials() (string, string, string) {
	return os.Getenv("INWX_USER_OTP"), os.Getenv("INWX_PASSWORD_OTP"), os.Getenv("INWX_OTPKEY")
}

func envOrDefault(env string, dflt string) string {
	if val := os.Getenv(env); val != "" {
		return val
	}
	return dflt
}

type componentTestData struct {
	t          *testing.T
	isOTPTest  bool
	dnsHandler *mocks.DNSServer
	inwxClient *mocks.INWXClient
	solver     webhook.Solver
}

func createComponentTestData(t *testing.T, isOTPTest bool) *componentTestData {
	assertEqual := func(exp, actual, name string) {
		if exp != actual { // not using testify to avoid leaking credentials
			t.Errorf("Credential for %v is not equal", name)
		}
	}
	dnsHandler := mocks.NewDNSServer(t)
	td := &componentTestData{
		t:          t,
		isOTPTest:  isOTPTest,
		dnsHandler: dnsHandler,
	}
	if td.hasUserNamePasswordEnv() || td.hasOTPEnv() {
		t.Log("Found credentials in env, will run integration test against INWX API")
		td.solver = solver.New() // real integration test
	} else {
		t.Log("Found no credentials in env, will run test without INWX API")
		// mock calls to inwx client
		td.inwxClient = mocks.NewINWXClient(t)
		mockINWXClientBuilder := func(cfg *solver.Config, creds *solver.Credentials) solver.INWXClient {
			var expUname, expPass, expOTP string
			if isOTPTest {
				expUname, expPass, expOTP = td.safeOTPCredentials()
				assertEqual(expOTP, creds.OTPKey, "OTPKey")
			} else {
				expUname, expPass = td.safeUserPassCredentials()
			}
			assertEqual(expUname, creds.Username, "Username")
			assertEqual(expPass, creds.Password, "Password")
			return td.inwxClient
		}
		td.solver = solver.NewWithInwxClient(mockINWXClientBuilder)
	}
	return td
}

func (td *componentTestData) secretConfig(withOTP bool) ([]byte, string) {
	configData := testConfig{UsernameSecretKeyRef: keyRef("username"), PasswordSecretKeyRef: keyRef("password")}
	var data map[string][]byte
	fNameFmtArg := ""
	if withOTP {
		fNameFmtArg = "otp-"
		configData.OTPKeySecretKeyRef = keyRef("otpKey")
		user, pass, otpKey := td.safeOTPCredentials()
		data = map[string][]byte{"username": []byte(user), "password": []byte(pass), "otpKey": []byte(otpKey)}
	} else {
		user, pass := td.safeUserPassCredentials()
		data = map[string][]byte{"username": []byte(user), "password": []byte(pass)}
	}
	configJSON := jsonBytesWithSandboxAndTTL300(td.t, &configData)
	sec := corev1.Secret{
		TypeMeta:   v1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: v1.ObjectMeta{Name: secretKeyRefName},
		Data:       data,
	}
	fd := writeSecretConfigToDir(td.t, fmt.Sprintf("inwx-%ssecret.yaml", fNameFmtArg), sec)
	return configJSON, fd
}

func (td *componentTestData) directConfig(withOTP bool) []byte {
	var configData testConfig
	if withOTP {
		user, pass, otpKey := td.safeOTPCredentials()
		configData = testConfig{Username: user, Password: pass, OTPKey: otpKey}
	} else {
		user, pass := td.safeUserPassCredentials()
		configData = testConfig{Username: user, Password: pass}
	}
	return jsonBytesWithSandboxAndTTL300(td.t, &configData)
}

func (td *componentTestData) safeOTPCredentials() (string, string, string) {
	if td.hasOTPEnv() {
		return otpCredentials()
	}
	return "testuser", "testpass", "testOTP"
}

func (td *componentTestData) safeUserPassCredentials() (string, string) {
	if td.hasUserNamePasswordEnv() {
		return usernamePassCredentials()
	}
	return "testuser", "testpass"
}

func (td *componentTestData) hasUserNamePasswordEnv() bool {
	user, _ := usernamePassCredentials()
	return user != "" && user != "test-user"
}
func (td *componentTestData) hasOTPEnv() bool {
	user, _, _ := otpCredentials()
	return user != "" && user != "test-user-otp"
}

func (td *componentTestData) expectINWXUserPasswordCalls() {
	td.expectCommonINWXCalls()
}
func (td *componentTestData) expectCommonINWXCalls() {
	if td.inwxClient == nil {
		return
	}
	td.inwxClient.EXPECT().Login().Return(nil)
	td.inwxClient.EXPECT().NameserverCreateRecord(mock.Anything).Return("something", nil)
	td.inwxClient.EXPECT().Logout()
	mockResp := &goinwx.NameserverInfoResponse{
		Records: []goinwx.NameserverRecord{
			{ID: "1", Name: "_acme-challenge", Type: "TXT"},
			{ID: "2", Name: "_acme-challenge2", Type: "TXT"},
		},
	}
	td.inwxClient.EXPECT().NameserverInfo(mock.Anything).Return(mockResp, nil)
	td.inwxClient.EXPECT().NameserverDeleteRecord(mock.Anything).Return(nil)
}

func (td *componentTestData) expectINWXOTPCalls() {
	if td.inwxClient == nil {
		return
	}
	td.expectCommonINWXCalls()
	td.inwxClient.EXPECT().TryToUnlockWithOTPKey(mock.Anything, mock.Anything).Return(nil, nil)
}
func (td *componentTestData) expectDNSServerCalls(fqdn string) {
	cnt := 0
	td.dnsHandler.EXPECT().ServeDNS(mock.Anything, mock.MatchedBy(func(req *dns.Msg) bool { return req.Question[0].Name == fqdn })).
		Run(func(w dns.ResponseWriter, req *dns.Msg) {
			m := new(dns.Msg).SetReply(req)
			defer w.WriteMsg(m)
			if cnt >= 2 && cnt < 4 {
				txtRec := fmt.Sprintf("%s %d IN TXT %s", req.Question[0].Name, 1, "123d==")
				txtRR, _ := dns.NewRR(txtRec)
				m.Answer = append(m.Answer, txtRR)
			}
			cnt++
		}).Return()
}
