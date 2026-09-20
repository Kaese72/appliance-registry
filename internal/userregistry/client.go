// Package userregistry is a minimal client for the one cloud-user-registry
// endpoint this service needs: asking whether a user is currently a member of
// a group. appliance-registry has no access to that service's database, so
// this is how it learns who may access an appliance owned by a group.
package userregistry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Surname  string `json:"surname"`
	Email    string `json:"email"`
}

// Access is cloud-user-registry's answer. User is only set when IsMember is
// true.
type Access struct {
	IsMember bool  `json:"isMember"`
	User     *User `json:"user,omitempty"`
}

type Client interface {
	GetGroupMember(ctx context.Context, groupID int64, userID int64) (Access, error)
}

type httpClient struct {
	baseURL      string
	serviceToken string
	httpClient   *http.Client
}

func NewClient(baseURL string, serviceToken string) Client {
	return httpClient{baseURL: baseURL, serviceToken: serviceToken, httpClient: &http.Client{Timeout: 10 * time.Second}}
}

func (c httpClient) GetGroupMember(ctx context.Context, groupID int64, userID int64) (Access, error) {
	url := fmt.Sprintf("%s/cloud-user-registry/v0/internal/groups/%s/members/%s", c.baseURL, strconv.FormatInt(groupID, 10), strconv.FormatInt(userID, 10))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Access{}, err
	}
	req.Header.Set("Authorization", "Bearer "+c.serviceToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return Access{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Access{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Access{}, fmt.Errorf("cloud-user-registry membership lookup failed with status %d: %s", resp.StatusCode, string(body))
	}
	var out Access
	if err := json.Unmarshal(body, &out); err != nil {
		return Access{}, err
	}
	return out, nil
}
