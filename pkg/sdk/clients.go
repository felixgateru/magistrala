// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	apiutil "github.com/absmach/supermq/api/http/util"
	"github.com/absmach/supermq/pkg/errors"
)

const (
	permissionsEndpoint = "permissions"
	clientsEndpoint     = "clients"
	connectEndpoint     = "connect"
	disconnectEndpoint  = "disconnect"
	identifyEndpoint    = "identify"
	rolesEndpoint       = "roles"
	actionsEndpoint     = "actions"
)

// Client represents supermq client.
type Client struct {
	ID          string                 `json:"id,omitempty"`
	Name        string                 `json:"name,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	DomainID    string                 `json:"domain_id,omitempty"`
	ParentGroup string                 `json:"parent_group_id,omitempty"`
	Credentials ClientCredentials      `json:"credentials"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at,omitempty"`
	UpdatedAt   time.Time              `json:"updated_at,omitempty"`
	UpdatedBy   string                 `json:"updated_by,omitempty"`
	Status      string                 `json:"status,omitempty"`
	Permissions []string               `json:"permissions,omitempty"`
}

type ClientCredentials struct {
	Identity string `json:"identity,omitempty"`
	Secret   string `json:"secret,omitempty"`
}

func (sdk mgSDK) CreateClient(client Client, domainID, token string) (Client, errors.SDKError) {
	data, err := json.Marshal(client)
	if err != nil {
		return Client{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint)

	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusCreated)
	if sdkerr != nil {
		return Client{}, sdkerr
	}

	client = Client{}
	if err := json.Unmarshal(body, &client); err != nil {
		return Client{}, errors.NewSDKError(err)
	}

	return client, nil
}

func (sdk mgSDK) CreateClients(clients []Client, domainID, token string) ([]Client, errors.SDKError) {
	data, err := json.Marshal(clients)
	if err != nil {
		return []Client{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, "bulk")

	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return []Client{}, sdkerr
	}

	var ctr createClientsRes
	if err := json.Unmarshal(body, &ctr); err != nil {
		return []Client{}, errors.NewSDKError(err)
	}

	return ctr.Clients, nil
}

func (sdk mgSDK) Clients(pm PageMetadata, domainID, token string) (ClientsPage, errors.SDKError) {
	endpoint := fmt.Sprintf("%s/%s", domainID, clientsEndpoint)
	url, err := sdk.withQueryParams(sdk.clientsURL, endpoint, pm)
	if err != nil {
		return ClientsPage{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return ClientsPage{}, sdkerr
	}

	var cp ClientsPage
	if err := json.Unmarshal(body, &cp); err != nil {
		return ClientsPage{}, errors.NewSDKError(err)
	}

	return cp, nil
}

func (sdk mgSDK) Client(id, domainID, token string) (Client, errors.SDKError) {
	if id == "" {
		return Client{}, errors.NewSDKError(apiutil.ErrMissingID)
	}
	url := fmt.Sprintf("%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id)

	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Client{}, sdkerr
	}

	var t Client
	if err := json.Unmarshal(body, &t); err != nil {
		return Client{}, errors.NewSDKError(err)
	}

	return t, nil
}

func (sdk mgSDK) UpdateClient(t Client, domainID, token string) (Client, errors.SDKError) {
	if t.ID == "" {
		return Client{}, errors.NewSDKError(apiutil.ErrMissingID)
	}
	url := fmt.Sprintf("%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, t.ID)

	data, err := json.Marshal(t)
	if err != nil {
		return Client{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(http.MethodPatch, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return Client{}, sdkerr
	}

	t = Client{}
	if err := json.Unmarshal(body, &t); err != nil {
		return Client{}, errors.NewSDKError(err)
	}

	return t, nil
}

func (sdk mgSDK) UpdateClientTags(t Client, domainID, token string) (Client, errors.SDKError) {
	data, err := json.Marshal(t)
	if err != nil {
		return Client{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/tags", sdk.clientsURL, domainID, clientsEndpoint, t.ID)

	_, body, sdkerr := sdk.processRequest(http.MethodPatch, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return Client{}, sdkerr
	}

	t = Client{}
	if err := json.Unmarshal(body, &t); err != nil {
		return Client{}, errors.NewSDKError(err)
	}

	return t, nil
}

func (sdk mgSDK) UpdateClientSecret(id, secret, domainID, token string) (Client, errors.SDKError) {
	ucsr := updateClientSecretReq{Secret: secret}

	data, err := json.Marshal(ucsr)
	if err != nil {
		return Client{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/secret", sdk.clientsURL, domainID, clientsEndpoint, id)

	_, body, sdkerr := sdk.processRequest(http.MethodPatch, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return Client{}, sdkerr
	}

	var t Client
	if err = json.Unmarshal(body, &t); err != nil {
		return Client{}, errors.NewSDKError(err)
	}

	return t, nil
}

func (sdk mgSDK) EnableClient(id, domainID, token string) (Client, errors.SDKError) {
	return sdk.changeClientStatus(id, enableEndpoint, domainID, token)
}

func (sdk mgSDK) DisableClient(id, domainID, token string) (Client, errors.SDKError) {
	return sdk.changeClientStatus(id, disableEndpoint, domainID, token)
}

func (sdk mgSDK) changeClientStatus(id, status, domainID, token string) (Client, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, status)

	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Client{}, sdkerr
	}

	t := Client{}
	if err := json.Unmarshal(body, &t); err != nil {
		return Client{}, errors.NewSDKError(err)
	}

	return t, nil
}

func (sdk mgSDK) SetClientParent(id, domainID, groupID, token string) errors.SDKError {
	scpg := parentGroupReq{ParentGroupID: groupID}
	data, err := json.Marshal(scpg)
	if err != nil {
		return errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, parentEndpoint)
	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusOK)

	return sdkerr
}

func (sdk mgSDK) RemoveClientParent(id, domainID, groupID, token string) errors.SDKError {
	rcpg := parentGroupReq{ParentGroupID: groupID}
	data, err := json.Marshal(rcpg)
	if err != nil {
		return errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, parentEndpoint)
	_, _, sdkerr := sdk.processRequest(http.MethodDelete, url, token, data, nil, http.StatusNoContent)

	return sdkerr
}

func (sdk mgSDK) DeleteClient(id, domainID, token string) errors.SDKError {
	if id == "" {
		return errors.NewSDKError(apiutil.ErrMissingID)
	}
	url := fmt.Sprintf("%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id)
	_, _, sdkerr := sdk.processRequest(http.MethodDelete, url, token, nil, nil, http.StatusNoContent)
	return sdkerr
}

func (sdk mgSDK) ListUserClients(userID, domainID string, pm PageMetadata, token string) (ClientsPage, errors.SDKError) {
	url, err := sdk.withQueryParams(sdk.clientsURL, fmt.Sprintf("%s/%s/%s/%s", domainID, usersEndpoint, userID, clientsEndpoint), pm)
	if err != nil {
		return ClientsPage{}, errors.NewSDKError(err)
	}
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return ClientsPage{}, sdkerr
	}
	cp := ClientsPage{}
	if err := json.Unmarshal(body, &cp); err != nil {
		return ClientsPage{}, errors.NewSDKError(err)
	}

	return cp, nil
}

func (sdk mgSDK) CreateClientRole(id, domainID string, rq RoleReq, token string) (Role, errors.SDKError) {
	data, err := json.Marshal(rq)
	if err != nil {
		return Role{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, rolesEndpoint)
	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusCreated)
	if sdkerr != nil {
		return Role{}, sdkerr
	}

	role := Role{}
	if err := json.Unmarshal(body, &role); err != nil {
		return Role{}, errors.NewSDKError(err)
	}

	return role, nil
}

func (sdk mgSDK) ClientRoles(id, domainID string, pm PageMetadata, token string) (RolesPage, errors.SDKError) {
	endpoint := fmt.Sprintf("%s/%s/%s/%s", domainID, clientsEndpoint, id, rolesEndpoint)
	url, err := sdk.withQueryParams(sdk.clientsURL, endpoint, pm)
	if err != nil {
		return RolesPage{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return RolesPage{}, sdkerr
	}

	var rp RolesPage
	if err := json.Unmarshal(body, &rp); err != nil {
		return RolesPage{}, errors.NewSDKError(err)
	}

	return rp, nil
}

func (sdk mgSDK) ClientRole(id, roleName, domainID, token string) (Role, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, rolesEndpoint, roleName)
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Role{}, sdkerr
	}

	var role Role
	if err := json.Unmarshal(body, &role); err != nil {
		return Role{}, errors.NewSDKError(err)
	}

	return role, nil
}

func (sdk mgSDK) UpdateClientRole(id, roleName, newName, domainID string, token string) (Role, errors.SDKError) {
	ucr := updateRoleNameReq{Name: newName}
	data, err := json.Marshal(ucr)
	if err != nil {
		return Role{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, rolesEndpoint, roleName)
	_, body, sdkerr := sdk.processRequest(http.MethodPut, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return Role{}, sdkerr
	}

	role := Role{}
	if err := json.Unmarshal(body, &role); err != nil {
		return Role{}, errors.NewSDKError(err)
	}

	return role, nil
}

func (sdk mgSDK) DeleteClientRole(id, roleName, domainID, token string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, rolesEndpoint, roleName)
	_, _, sdkerr := sdk.processRequest(http.MethodDelete, url, token, nil, nil, http.StatusNoContent)

	return sdkerr
}

func (sdk mgSDK) AddClientRoleActions(id, roleName, domainID string, actions []string, token string) ([]string, errors.SDKError) {
	acra := roleActionsReq{Actions: actions}
	data, err := json.Marshal(acra)
	if err != nil {
		return []string{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, rolesEndpoint, roleName, actionsEndpoint)
	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return []string{}, sdkerr
	}

	res := roleActionsRes{}
	if err := json.Unmarshal(body, &res); err != nil {
		return []string{}, errors.NewSDKError(err)
	}

	return res.Actions, nil
}

func (sdk mgSDK) ClientRoleActions(id, roleName, domainID string, token string) ([]string, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, rolesEndpoint, roleName, actionsEndpoint)
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return nil, sdkerr
	}

	res := roleActionsRes{}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, errors.NewSDKError(err)
	}

	return res.Actions, nil
}

func (sdk mgSDK) RemoveClientRoleActions(id, roleName, domainID string, actions []string, token string) errors.SDKError {
	rcra := roleActionsReq{Actions: actions}
	data, err := json.Marshal(rcra)
	if err != nil {
		return errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, rolesEndpoint, roleName, actionsEndpoint, "delete")
	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusNoContent)

	return sdkerr
}

func (sdk mgSDK) RemoveAllClientRoleActions(id, roleName, domainID, token string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, rolesEndpoint, roleName, actionsEndpoint, "delete-all")
	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, token, nil, nil, http.StatusNoContent)

	return sdkerr
}

func (sdk mgSDK) AddClientRoleMembers(id, roleName, domainID string, members []string, token string) ([]string, errors.SDKError) {
	acrm := roleMembersReq{Members: members}
	data, err := json.Marshal(acrm)
	if err != nil {
		return []string{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, rolesEndpoint, roleName, membersEndpoint)
	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return []string{}, sdkerr
	}

	res := roleMembersRes{}
	if err := json.Unmarshal(body, &res); err != nil {
		return []string{}, errors.NewSDKError(err)
	}

	return res.Members, nil
}

func (sdk mgSDK) ClientRoleMembers(id, roleName, domainID string, pm PageMetadata, token string) (RoleMembersPage, errors.SDKError) {
	endpoint := fmt.Sprintf("%s/%s/%s/%s/%s/%s", domainID, clientsEndpoint, id, rolesEndpoint, roleName, membersEndpoint)
	url, err := sdk.withQueryParams(sdk.clientsURL, endpoint, pm)
	if err != nil {
		return RoleMembersPage{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return RoleMembersPage{}, sdkerr
	}

	res := RoleMembersPage{}
	if err := json.Unmarshal(body, &res); err != nil {
		return RoleMembersPage{}, errors.NewSDKError(err)
	}

	return res, nil
}

func (sdk mgSDK) RemoveClientRoleMembers(id, roleName, domainID string, members []string, token string) errors.SDKError {
	rcrm := roleMembersReq{Members: members}
	data, err := json.Marshal(rcrm)
	if err != nil {
		return errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, rolesEndpoint, roleName, membersEndpoint, "delete")
	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusNoContent)

	return sdkerr
}

func (sdk mgSDK) RemoveAllClientRoleMembers(id, roleName, domainID, token string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, id, rolesEndpoint, roleName, membersEndpoint, "delete-all")
	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, token, nil, nil, http.StatusNoContent)

	return sdkerr
}

func (sdk mgSDK) AvailableClientRoleActions(domainID, token string) ([]string, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s/%s", sdk.clientsURL, domainID, clientsEndpoint, rolesEndpoint, "available-actions")
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return nil, sdkerr
	}

	res := availableRoleActionsRes{}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, errors.NewSDKError(err)
	}

	return res.AvailableActions, nil
}
