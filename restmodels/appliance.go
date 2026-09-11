package restmodels

import "time"

// RegisterApplianceRequest is the payload to register a new Appliance -
// see the README's "Registration".
type RegisterApplianceRequest struct {
	Name string `json:"name" minLength:"1" maxLength:"255"`
}

// RegisterApplianceResponse carries the one-time claim token alongside the
// created Appliance. ClaimToken is not retrievable again - see the
// README's "Claim token" model.
type RegisterApplianceResponse struct {
	ApplianceResponse
	ClaimToken          string    `json:"claimToken"`
	ClaimTokenExpiresAt time.Time `json:"claimTokenExpiresAt"`
}

// ApplianceResponse describes an Appliance without any secret material -
// see the README's "Appliance" model.
type ApplianceResponse struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Hostname   string     `json:"hostname"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"createdAt"`
	ClaimedAt  *time.Time `json:"claimedAt,omitempty"`
	LastSeenAt *time.Time `json:"lastSeenAt,omitempty"`
}

// ClaimApplianceResponse is returned once, to the appliance itself, at the
// end of a successful claim (and again, on demand, by rotate) - see the
// README's "Claiming" and "Revocation / rotation".
type ClaimApplianceResponse struct {
	ApplianceSecret string `json:"applianceSecret"`
	Hostname        string `json:"hostname"`
	TunnelURL       string `json:"tunnelUrl"`
}

// ArgoCDPluginGetParamsRequest is the body ArgoCD's ApplicationSet Plugin
// generator sends to POST .../api/v1/getparams.execute. This service
// ignores its contents - the active-appliance list doesn't depend on
// anything the generator would pass in - but needs both fields to exist
// (including Input, which ArgoCD always sends alongside
// ApplicationSetName) so huma's generated schema, which defaults to
// additionalProperties: false, doesn't reject the request body with a 422.
type ArgoCDPluginGetParamsRequest struct {
	ApplicationSetName string                 `json:"applicationSetName,omitempty"`
	Input              map[string]interface{} `json:"input,omitempty"`
}

// ArgoCDPluginParameter is one entry of output.parameters in a Plugin
// generator response - see
// https://argo-cd.readthedocs.io/en/stable/operator-manual/applicationset/Generators-Plugin/.
// Field names become template variables ({{.id}}, {{.hostname}}, {{.name}})
// in the ApplicationSet's template - see huemie-gitops-base's
// cloud/application-crds/applicationset-cloud-connect-server-fleet.yaml.
type ArgoCDPluginParameter struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	Name     string `json:"name"`
}

type ArgoCDPluginGetParamsResponse struct {
	Output struct {
		Parameters []ArgoCDPluginParameter `json:"parameters"`
	} `json:"output"`
}
