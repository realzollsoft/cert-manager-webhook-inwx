package solver

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	certmgrv1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/nrdcg/goinwx"
	"github.com/realzollsoft/cert-manager-webhook-inwx/internal/util"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

type (
	Credentials struct {
		Username string
		Password string
		OTPKey   string
	}

	solver struct {
		k8sCl           kubernetes.Interface
		buildK8sClient  K8sClientFactory
		buildINWXClient INWXClientFactory
	}

	Config struct {
		// These fields will be set by users in the
		// `issuer.spec.acme.dns01.providers.webhook.config` field.
		TTL                  int                         `json:"ttl,omitempty"`
		Sandbox              bool                        `json:"sandbox,omitempty"`
		FQDNNaming           bool                        `json:"fqdnNaming,omitempty"`
		Username             string                      `json:"username"`
		Password             string                      `json:"password"`
		OTPKey               string                      `json:"otpKey"`
		UsernameSecretKeyRef certmgrv1.SecretKeySelector `json:"usernameSecretKeyRef"`
		PasswordSecretKeyRef certmgrv1.SecretKeySelector `json:"passwordSecretKeyRef"`
		OTPKeySecretKeyRef   certmgrv1.SecretKeySelector `json:"otpKeySecretKeyRef"`
	}

	K8sClientFactory  func(c *rest.Config) (kubernetes.Interface, error)
	INWXClientFactory func(cfg *Config, creds *Credentials) INWXClient
)

var _ webhook.Solver = (*solver)(nil)

var defaultConfig = Config{
	TTL:     300,
	Sandbox: false,
}

func NewWithInwxClient(inwxFn INWXClientFactory) *solver {
	k8sFn := func(c *rest.Config) (kubernetes.Interface, error) { return kubernetes.NewForConfig(c) }
	return &solver{
		buildK8sClient:  k8sFn,
		buildINWXClient: inwxFn,
	}
}

func New() *solver {
	inwxFn := func(cfg *Config, creds *Credentials) INWXClient { return NewClient(cfg, creds) }
	return NewWithInwxClient(inwxFn)
}

func (s *solver) Name() string {
	return "inwx"
}

func (s *solver) Present(ch *v1alpha1.ChallengeRequest) error {
	client, cfg, err := s.newClientFromChallenge(ch)
	if err != nil {
		return err
	}

	defer client.Logout()

	request := &goinwx.NameserverRecordRequest{
		Domain:  util.TrimTrailingDots(ch.ResolvedZone),
		Name:    util.GatherName(cfg.FQDNNaming, ch.ResolvedFQDN, ch.ResolvedZone),
		Type:    "TXT",
		Content: ch.Key,
		TTL:     cfg.TTL,
	}

	_, err = client.NameserverCreateRecord(request)
	if err != nil {
		return s.handleCreateError(ch, err)
	}
	klog.V(2).Infof("created DNS record %v", request)
	return nil
}

func (s *solver) handleCreateError(ch *v1alpha1.ChallengeRequest, err error) error {
	switch er := err.(type) {
	case *goinwx.ErrorResponse:
		if er.Message == "Object exists" {
			klog.Warningf("key already exists for host %v", ch.ResolvedFQDN)
			return nil
		}
		klog.Error(err)
		return fmt.Errorf("%v", err)
	default:
		klog.Error(err)
		return fmt.Errorf("%v", err)
	}
}

func (s *solver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	client, cfg, err := s.newClientFromChallenge(ch)
	if err != nil {
		return err
	}
	defer client.Logout()
	infoReq := &goinwx.NameserverInfoRequest{
		Domain: util.TrimTrailingDots(ch.ResolvedZone),
		Name:   util.GatherName(cfg.FQDNNaming, ch.ResolvedFQDN, ch.ResolvedZone),
		Type:   "TXT",
	}
	response, err := client.NameserverInfo(infoReq)
	if err != nil {
		klog.Error(err)
		return fmt.Errorf("%v", err)
	}

	var lastErr error
	for _, record := range response.Records {
		err = client.NameserverDeleteRecord(record.ID)
		if err != nil {
			klog.Error(err)
			lastErr = fmt.Errorf("%v", err)
		}
		klog.V(2).Infof("deleted DNS record %v", record)
	}

	return lastErr
}

func (s *solver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := s.buildK8sClient(kubeClientConfig)
	if err != nil {
		return err
	}
	s.k8sCl = cl

	return nil
}

func (s *solver) getCredentials(config *Config, ns string) (*Credentials, error) {
	creds := Credentials{}

	if config.Username != "" {
		creds.Username = config.Username
	} else {
		uName, err := s.retrieveSecretValue(ns, config.UsernameSecretKeyRef)
		if err != nil {
			return nil, err
		}
		creds.Username = uName
	}

	if config.Password != "" {
		creds.Password = config.Password
	} else {
		pw, err := s.retrieveSecretValue(ns, config.PasswordSecretKeyRef)
		if err != nil {
			return nil, err
		}
		creds.Password = pw
	}

	if config.OTPKey != "" {
		creds.OTPKey = config.OTPKey
	} else if config.OTPKeySecretKeyRef.Key != "" {
		otpKey, err := s.retrieveSecretValue(ns, config.OTPKeySecretKeyRef)
		if err != nil {
			return nil, err
		}
		creds.OTPKey = otpKey
	}

	return &creds, nil
}

func (s *solver) retrieveSecretValue(ns string, selector certmgrv1.SecretKeySelector) (string, error) {
	secret, err := s.k8sCl.CoreV1().Secrets(ns).Get(context.Background(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to load secret %v", ns+"/"+selector.Name)
	}
	bvalue, ok := secret.Data[selector.Key]
	if ok {
		return string(bvalue), nil
	}
	value, ok := secret.StringData[selector.Key]
	if ok {
		return value, nil
	}
	return "", fmt.Errorf("no key %v in secret %v", selector, ns+"/"+selector.Name)
}

func loadConfig(cfgBytes []byte) (Config, error) {
	cfg := Config{}
	if cfgBytes == nil {
		return defaultConfig, nil
	}
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	if cfg.TTL == 0 {
		cfg.TTL = defaultConfig.TTL
	} else if cfg.TTL < 300 {
		klog.Warningf("TTL must be greater or equal than 300. Using default %v", defaultConfig.TTL)
		cfg.TTL = defaultConfig.TTL
	}

	return cfg, nil
}

func (s *solver) newClientFromChallenge(ch *v1alpha1.ChallengeRequest) (INWXClient, *Config, error) {
	cfg, err := loadConfig(ch.Config.Raw)
	if err != nil {
		return nil, nil, err
	}

	klog.V(5).Infof("decoded config: %v", cfg)

	creds, err := s.getCredentials(&cfg, ch.ResourceNamespace)
	if err != nil {
		return nil, &cfg, fmt.Errorf("error getting credentials: %v", err)
	}
	c := s.buildINWXClient(&cfg, creds)

	err = c.Login()
	if err != nil {
		klog.Error(err)
		return nil, &cfg, fmt.Errorf("%v", err)
	}

	if creds.OTPKey != "" {
		err, formattedError := c.TryToUnlockWithOTPKey(creds.OTPKey, true)
		if err != nil {
			return nil, &cfg, formattedError
		}
	}

	klog.V(3).Infof("logged in at INWX API (sandbox: %v)", cfg.Sandbox)

	return c, &cfg, nil
}
