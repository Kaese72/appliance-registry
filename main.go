package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Kaese72/appliance-registry/internal/appliancewebapp"
	"github.com/Kaese72/appliance-registry/internal/config"
	"github.com/Kaese72/appliance-registry/internal/k8ssecrets"
	"github.com/Kaese72/appliance-registry/internal/logging"
	"github.com/Kaese72/appliance-registry/internal/persistence/mariadb"
	"github.com/Kaese72/appliance-registry/internal/tokens"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humamux"
	"github.com/gorilla/mux"

	_ "go.elastic.co/apm/module/apmsql/mysql"
)

func main() {
	if err := config.Loaded.Validate(); err != nil {
		logging.Error(err.Error(), context.TODO())
		os.Exit(1)
	}

	dbPersistence, err := mariadb.NewMariadbPersistence(config.Loaded.Database)
	if err != nil {
		logging.Error(err.Error(), context.Background())
		os.Exit(1)
	}

	keyBytes, err := os.ReadFile(config.Loaded.Auth.UseTokenRSAPublicKeyPath)
	if err != nil {
		logging.Error("failed to read RSA public key: "+err.Error(), context.Background())
		os.Exit(1)
	}
	publicKey, err := tokens.LoadRSAPublicKey(keyBytes)
	if err != nil {
		logging.Error("failed to parse RSA public key: "+err.Error(), context.Background())
		os.Exit(1)
	}

	secretWriter := k8ssecrets.NewSecretWriter(config.Loaded.Kubernetes.Namespace)
	claimTokenExpiry := time.Duration(config.Loaded.Auth.ClaimTokenExpiryMinutes) * time.Minute
	exchangeCodeExpiry := time.Duration(config.Loaded.Auth.ExchangeCodeExpiryMinutes) * time.Minute

	app := appliancewebapp.NewWebApp(
		dbPersistence,
		publicKey,
		tokens.ParseTokenList(config.Loaded.Auth.ServiceTokens),
		tokens.ParseTokenList(config.Loaded.Auth.PluginTokens),
		claimTokenExpiry,
		exchangeCodeExpiry,
		config.Loaded.Hostname.BaseDomain,
		secretWriter,
	)

	router := mux.NewRouter()
	humaConfig := huma.DefaultConfig("appliance-registry", "1.0.0")
	humaConfig.OpenAPIPath = "/appliance-registry/openapi"
	humaConfig.DocsPath = "/appliance-registry/docs"
	api := humamux.New(router, humaConfig)

	huma.Post(api, "/appliance-registry/v0/appliances", app.Register)
	huma.Get(api, "/appliance-registry/v0/appliances", app.ListAppliances)
	huma.Post(api, "/appliance-registry/v0/appliances/enroll", app.Enroll)
	huma.Post(api, "/appliance-registry/v0/appliances/{applianceId:[0-9]+}/claim", app.Claim)
	huma.Post(api, "/appliance-registry/v0/appliances/{applianceId:[0-9]+}/enroll/redeem", app.EnrollRedeem)
	huma.Post(api, "/appliance-registry/v0/appliances/{applianceId:[0-9]+}/revoke", app.Revoke)
	huma.Post(api, "/appliance-registry/v0/appliances/{applianceId:[0-9]+}/rotate", app.RotateSecret)
	huma.Post(api, "/appliance-registry/v0/argocd-plugin/api/v1/getparams.execute", app.PluginGetParams)

	if err := http.ListenAndServe(fmt.Sprintf(":%d", config.Loaded.Port), router); err != nil {
		logging.Error(err.Error(), context.TODO())
	}
}
