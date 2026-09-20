package config

import (
	"context"
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/Kaese72/appliance-registry/internal/logging"
	"github.com/spf13/viper"
)

type DatabaseConfig struct {
	Host     string `json:"host" mapstructure:"host"`
	Port     int    `json:"port" mapstructure:"port"`
	User     string `json:"user" mapstructure:"user"`
	Password string `json:"password" mapstructure:"password"`
	Database string `json:"database" mapstructure:"database"`
}

func (conf DatabaseConfig) Validate() error {
	if conf.Host == "" {
		return errors.New("must supply database host")
	}
	return nil
}

// AuthConfig configures the four distinct callers this service
// authenticates - see the README's "Architecture" section:
//   - a logged-in user, via a use JWT issued by cloud-user-registry, verified
//     with UseTokenRSAPublicKeyPath
//   - a freshly-installed appliance, via a single-use claim token this
//     service generates itself (ClaimTokenExpiryMinutes controls its expiry)
//   - a generic internal service caller of the ListAppliances endpoint, via
//     ServiceTokens
//   - the ArgoCD ApplicationSet Plugin generator specifically, via
//     PluginTokens
//
// ServiceTokens and PluginTokens are deliberately separate credentials, not
// one shared secret: the plugin endpoint is reachable over the public
// internet (ArgoCD's control plane generally can't reach this service's
// in-cluster DNS - see huemie-gitops-base's cloud/application-crds/README.md),
// so a leak of that one token shouldn't also compromise whatever else might
// call the generic listing endpoint. Each is a comma-separated list rather
// than a single value so a token can be rotated by adding the new value
// everywhere before removing the old one, instead of a single synchronized
// cutover across this service and its callers' configuration.
type AuthConfig struct {
	UseTokenRSAPublicKeyPath  string `json:"use-token-rsa-public-key-path" mapstructure:"use-token-rsa-public-key-path"`
	ClaimTokenExpiryMinutes   int    `json:"claim-token-expiry-minutes" mapstructure:"claim-token-expiry-minutes"`
	ExchangeCodeExpiryMinutes int    `json:"exchange-code-expiry-minutes" mapstructure:"exchange-code-expiry-minutes"`
	ServiceTokens             string `json:"service-tokens" mapstructure:"service-tokens"`
	PluginTokens              string `json:"plugin-tokens" mapstructure:"plugin-tokens"`
}

func (conf AuthConfig) Validate() error {
	if conf.UseTokenRSAPublicKeyPath == "" {
		return errors.New("must supply auth use-token-rsa-public-key-path")
	}
	if conf.ServiceTokens == "" {
		return errors.New("must supply auth service-tokens")
	}
	if conf.PluginTokens == "" {
		return errors.New("must supply auth plugin-tokens")
	}
	return nil
}

// UserRegistryConfig points at cloud-user-registry's internal membership
// endpoint. ServiceToken must be one of that service's auth service-tokens.
type UserRegistryConfig struct {
	BaseURL      string `json:"base-url" mapstructure:"base-url"`
	ServiceToken string `json:"service-token" mapstructure:"service-token"`
}

func (conf UserRegistryConfig) Validate() error {
	if conf.BaseURL == "" {
		return errors.New("must supply user-registry base-url")
	}
	if conf.ServiceToken == "" {
		return errors.New("must supply user-registry service-token")
	}
	return nil
}

// HostnameConfig controls how appliance hostnames are allocated. Every
// appliance is reachable at <label>.<BaseDomain> once claimed - see the
// README's "Appliance" model.
type HostnameConfig struct {
	BaseDomain string `json:"base-domain" mapstructure:"base-domain"`
}

func (conf HostnameConfig) Validate() error {
	if conf.BaseDomain == "" {
		return errors.New("must supply hostname base-domain")
	}
	return nil
}

// KubernetesConfig points at the namespace this service is allowed to write
// cloud-connect-secret-<id> Secrets into - see the README's "Cloud-side
// cloud-connect-server provisioning" section. If the service is not running
// in-cluster (e.g. local development), Secret writes are skipped with a
// warning rather than failing startup.
type KubernetesConfig struct {
	Namespace string `json:"namespace" mapstructure:"namespace"`
}

func (conf KubernetesConfig) Validate() error {
	if conf.Namespace == "" {
		return errors.New("must supply kubernetes namespace")
	}
	return nil
}

type Config struct {
	Database     DatabaseConfig     `json:"database" mapstructure:"database"`
	Auth         AuthConfig         `json:"auth" mapstructure:"auth"`
	UserRegistry UserRegistryConfig `json:"user-registry" mapstructure:"user-registry"`
	Hostname     HostnameConfig     `json:"hostname" mapstructure:"hostname"`
	Kubernetes   KubernetesConfig   `json:"kubernetes" mapstructure:"kubernetes"`
	Port         int                `json:"port" mapstructure:"port"`
}

func (conf Config) Validate() error {
	if err := conf.Database.Validate(); err != nil {
		return err
	}
	if err := conf.Auth.Validate(); err != nil {
		return err
	}
	if err := conf.UserRegistry.Validate(); err != nil {
		return err
	}
	if err := conf.Hostname.Validate(); err != nil {
		return err
	}
	if err := conf.Kubernetes.Validate(); err != nil {
		return err
	}
	return nil
}

var Loaded Config

func init() {
	// We have elected to not use AutomaticEnv() because of https://github.com/spf13/viper/issues/584
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	viper.BindEnv("database.host")
	viper.BindEnv("database.port")
	viper.BindEnv("database.user")
	viper.BindEnv("database.password")
	viper.BindEnv("database.database")
	viper.SetDefault("database.port", 3306)
	viper.SetDefault("database.database", "applianceregistry")

	viper.BindEnv("auth.use-token-rsa-public-key-path")
	viper.BindEnv("auth.claim-token-expiry-minutes")
	viper.SetDefault("auth.claim-token-expiry-minutes", 60)
	viper.BindEnv("auth.exchange-code-expiry-minutes")
	viper.SetDefault("auth.exchange-code-expiry-minutes", 5)
	viper.BindEnv("auth.service-tokens")
	viper.BindEnv("auth.plugin-tokens")

	viper.BindEnv("user-registry.base-url")
	viper.BindEnv("user-registry.service-token")

	viper.BindEnv("hostname.base-domain")
	viper.SetDefault("hostname.base-domain", "appliance.humi.kaese.space")

	viper.BindEnv("kubernetes.namespace")
	viper.SetDefault("kubernetes.namespace", "huemie-cloud")

	viper.BindEnv("logging.stdout")
	viper.SetDefault("logging.stdout", true)
	viper.BindEnv("logging.http.url")

	viper.BindEnv("port")
	viper.SetDefault("port", 8080)

	err := viper.Unmarshal(&Loaded)
	if err != nil {
		logging.Error(err.Error(), context.TODO())
		os.Exit(1)
	}
}
