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
	domainsEndpoint = "domains"
	freezeEndpoint  = "freeze"
)

// Domain represents supermq domain.
type Domain struct {
	ID          string    `json:"id,omitempty"`
	Name        string    `json:"name,omitempty"`
	Metadata    Metadata  `json:"metadata,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	Alias       string    `json:"alias,omitempty"`
	Status      string    `json:"status,omitempty"`
	Permission  string    `json:"permission,omitempty"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
	Permissions []string  `json:"permissions,omitempty"`
}

func (sdk mgSDK) CreateDomain(domain Domain, token string) (Domain, errors.SDKError) {
	data, err := json.Marshal(domain)
	if err != nil {
		return Domain{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s", sdk.domainsURL, domainsEndpoint)

	_, body, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusCreated)
	if sdkerr != nil {
		return Domain{}, sdkerr
	}

	var d Domain
	if err := json.Unmarshal(body, &d); err != nil {
		return Domain{}, errors.NewSDKError(err)
	}
	return d, nil
}

func (sdk mgSDK) Domains(pm PageMetadata, token string) (DomainsPage, errors.SDKError) {
	url, err := sdk.withQueryParams(sdk.domainsURL, domainsEndpoint, pm)
	if err != nil {
		return DomainsPage{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return DomainsPage{}, sdkerr
	}

	var dp DomainsPage
	if err := json.Unmarshal(body, &dp); err != nil {
		return DomainsPage{}, errors.NewSDKError(err)
	}

	return dp, nil
}

func (sdk mgSDK) Domain(domainID, token string) (Domain, errors.SDKError) {
	if domainID == "" {
		return Domain{}, errors.NewSDKError(apiutil.ErrMissingID)
	}
	url := fmt.Sprintf("%s/%s/%s", sdk.domainsURL, domainsEndpoint, domainID)

	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return Domain{}, sdkerr
	}

	var domain Domain
	if err := json.Unmarshal(body, &domain); err != nil {
		return Domain{}, errors.NewSDKError(err)
	}

	return domain, nil
}

func (sdk mgSDK) UpdateDomain(domain Domain, token string) (Domain, errors.SDKError) {
	if domain.ID == "" {
		return Domain{}, errors.NewSDKError(apiutil.ErrMissingID)
	}
	url := fmt.Sprintf("%s/%s/%s", sdk.domainsURL, domainsEndpoint, domain.ID)

	data, err := json.Marshal(domain)
	if err != nil {
		return Domain{}, errors.NewSDKError(err)
	}

	_, body, sdkerr := sdk.processRequest(http.MethodPatch, url, token, data, nil, http.StatusOK)
	if sdkerr != nil {
		return Domain{}, sdkerr
	}

	var d Domain
	if err := json.Unmarshal(body, &d); err != nil {
		return Domain{}, errors.NewSDKError(err)
	}
	return d, nil
}

func (sdk mgSDK) EnableDomain(domainID, token string) errors.SDKError {
	return sdk.changeDomainStatus(token, domainID, enableEndpoint)
}

func (sdk mgSDK) DisableDomain(domainID, token string) errors.SDKError {
	return sdk.changeDomainStatus(token, domainID, disableEndpoint)
}
func (sdk mgSDK) FreezeDomain(domainID, token string) errors.SDKError {
	return sdk.changeDomainStatus(token, domainID, freezeEndpoint)
}

func (sdk mgSDK) changeDomainStatus(token, id, status string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, status)
	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, token, nil, nil, http.StatusOK)
	return sdkerr
}

func (sdk mgSDK) CreateDomainRole(id string, rq RoleReq, token string) (Role, errors.SDKError) {
	data, err := json.Marshal(rq)
	if err != nil {
		return Role{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s", sdk.domainsURL, domainsEndpoint, id)
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

func (sdk mgSDK) DomainRoles(id, token string) (RolesPage, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint)
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

func (sdk mgSDK) DomainRole(id, roleName, token string) (Role, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, roleName)
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

func (sdk mgSDK) UpdateDomainRole(id, roleName, newName string, token string) (Role, errors.SDKError) {
	ucr := updateRoleNameReq{Name: newName}
	data, err := json.Marshal(ucr)
	if err != nil {
		return Role{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, roleName)
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

func (sdk mgSDK) DeleteDomainRole(id, roleName, token string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, roleName)
	_, _, sdkerr := sdk.processRequest(http.MethodDelete, url, token, nil, nil, http.StatusNoContent)

	return sdkerr
}

func (sdk mgSDK) AddDomainRoleActions(id, roleName string, actions []string, token string) ([]string, errors.SDKError) {
	acra := roleActionsReq{Actions: actions}
	data, err := json.Marshal(acra)
	if err != nil {
		return []string{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, roleName, actionsEndpoint)
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

func (sdk mgSDK) DomainRoleActions(id, roleName string, token string) ([]string, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, roleName, actionsEndpoint)
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

func (sdk mgSDK) RemoveDomainRoleActions(id, roleName string, actions []string, token string) errors.SDKError {
	rcra := roleActionsReq{Actions: actions}
	data, err := json.Marshal(rcra)
	if err != nil {
		return errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, roleName, actionsEndpoint, "delete")
	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusOK)

	return sdkerr
}

func (sdk mgSDK) RemoveAllDomainRoleActions(id, roleName, token string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, roleName, actionsEndpoint, "delete-all")
	_, _, sdkerr := sdk.processRequest(http.MethodDelete, url, token, nil, nil, http.StatusOK)

	return sdkerr
}

func (sdk mgSDK) AddDomainRoleMembers(id, roleName string, members []string, token string) ([]string, errors.SDKError) {
	acrm := roleMembersReq{Members: members}
	data, err := json.Marshal(acrm)
	if err != nil {
		return []string{}, errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, roleName, membersEndpoint)
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

func (sdk mgSDK) DomainRoleMembers(id, roleName string, token string) ([]string, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, roleName, membersEndpoint)
	_, body, sdkerr := sdk.processRequest(http.MethodGet, url, token, nil, nil, http.StatusOK)
	if sdkerr != nil {
		return nil, sdkerr
	}

	res := roleMembersRes{}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, errors.NewSDKError(err)
	}

	return res.Members, nil
}

func (sdk mgSDK) RemoveDomainRoleMembers(id, roleName string, members []string, token string) errors.SDKError {
	rcrm := roleMembersReq{Members: members}
	data, err := json.Marshal(rcrm)
	if err != nil {
		return errors.NewSDKError(err)
	}

	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, roleName, membersEndpoint, "delete")
	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, token, data, nil, http.StatusOK)

	return sdkerr
}

func (sdk mgSDK) RemoveAllDomainRoleMembers(id, roleName, token string) errors.SDKError {
	url := fmt.Sprintf("%s/%s/%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, roleName, membersEndpoint, "delete-all")
	_, _, sdkerr := sdk.processRequest(http.MethodPost, url, token, nil, nil, http.StatusOK)

	return sdkerr
}

func (sdk mgSDK) AvailableDomainRoleActions(id, token string) ([]string, errors.SDKError) {
	url := fmt.Sprintf("%s/%s/%s/%s/%s", sdk.domainsURL, domainsEndpoint, id, rolesEndpoint, "available-actions")
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
