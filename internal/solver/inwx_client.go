package solver

import (
	"fmt"
	"time"

	"github.com/nrdcg/goinwx"
	"github.com/pquerna/otp/totp"
	"k8s.io/klog/v2"
)

type INWXClient interface {
	Login() error
	Logout()
	NameserverCreateRecord(req *goinwx.NameserverRecordRequest) (string, error)
	NameserverInfo(req *goinwx.NameserverInfoRequest) (*goinwx.NameserverInfoResponse, error)
	NameserverDeleteRecord(id string) error
	TryToUnlockWithOTPKey(otpKey string, retryAfterPauseToSatisfyInwxSingleOTPKeyUsagePolicy bool) (error, error)
}

type inwxClient struct {
	client *goinwx.Client
	cfg    *Config
}

func NewClient(cfg *Config, creds *Credentials) *inwxClient {
	opts := &goinwx.ClientOptions{Sandbox: cfg.Sandbox}
	client := goinwx.NewClient(creds.Username, creds.Password, opts)

	return &inwxClient{
		client: client,
		cfg:    cfg,
	}
}

func (c *inwxClient) Login() error {
	_, err := c.client.Account.Login()
	return err
}

func (c *inwxClient) Logout() {
	if err := c.client.Account.Logout(); err != nil {
		klog.Errorf("failed to log out from INWX API (sandbox: %v): %v", c.cfg.Sandbox, err)
		return
	}
	klog.V(3).Infof("logged out from INWX API (sandbox: %v)", c.cfg.Sandbox)
}
func (c *inwxClient) NameserverCreateRecord(req *goinwx.NameserverRecordRequest) (string, error) {
	return c.client.Nameservers.CreateRecord(req)
}

func (c *inwxClient) NameserverInfo(req *goinwx.NameserverInfoRequest) (*goinwx.NameserverInfoResponse, error) {
	return c.client.Nameservers.Info(req)
}
func (c *inwxClient) NameserverDeleteRecord(id string) error {
	return c.client.Nameservers.DeleteRecord(id)
}

func (c *inwxClient) TryToUnlockWithOTPKey(otpKey string, retryAfterPauseToSatisfyInwxSingleOTPKeyUsagePolicy bool) (error, error) {
	tan, err := totp.GenerateCode(otpKey, time.Now())
	if err != nil {
		klog.Error(err)
		return nil, fmt.Errorf("error generating opt-key: %v", err)
	}

	err = c.client.Account.Unlock(tan)

	if err != nil && retryAfterPauseToSatisfyInwxSingleOTPKeyUsagePolicy {
		time.Sleep(30 * time.Second)
		return c.TryToUnlockWithOTPKey(otpKey, false)
	} else if err != nil {
		klog.Error(err)
		return err, fmt.Errorf("error Unlock opt-key: %v", err)
	}

	return nil, nil
}
