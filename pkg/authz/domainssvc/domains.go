// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package domainssvc

import (
	"context"

	"github.com/absmach/supermq/domains"
	grpcDomainsV1 "github.com/absmach/supermq/internal/grpc/domains/v1"
	"github.com/absmach/supermq/pkg/authn"
	"github.com/absmach/supermq/pkg/authz"
	"github.com/absmach/supermq/pkg/errors"
	svcerr "github.com/absmach/supermq/pkg/errors/service"
	"github.com/absmach/supermq/pkg/grpcclient"
	"github.com/absmach/supermq/pkg/policies"
)

type domainCheck struct {
	domains grpcDomainsV1.DomainsServiceClient
	authz   authz.Authorization
}

var _ authz.DomainCheck = (*domainCheck)(nil)

func NewDomainCheck(ctx context.Context, authz authz.Authorization, cfg grpcclient.Config) (authz.DomainCheck, grpcclient.Handler, error) {
	domainsClient, domainsHandler, err := grpcclient.SetupDomainsClient(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}

	return domainCheck{
			domains: domainsClient,
			authz:   authz,
		},
		domainsHandler, nil
}

func (d domainCheck) CheckDomain(ctx context.Context, session authn.Session) error {
	res, err := d.domains.RetrieveEntity(ctx, &grpcDomainsV1.RetrieveEntityReq{Id: session.DomainID})
	if err != nil {
		return errors.Wrap(svcerr.ErrViewEntity, err)
	}

	switch domains.Status(res.Status) {
	case domains.FreezeStatus:
		return d.authz.Authorize(ctx, authz.PolicyReq{
			Subject:     session.UserID,
			SubjectType: policies.UserType,
			SubjectKind: policies.UsersKind,
			Permission:  policies.AdminPermission,
			Object:      policies.SuperMQObject,
			ObjectType:  policies.PlatformType,
		})
	case domains.DisabledStatus:
		return d.authz.Authorize(ctx, authz.PolicyReq{
			Subject:     session.DomainUserID,
			SubjectType: policies.UserType,
			SubjectKind: policies.UsersKind,
			Permission:  policies.AdminPermission,
			Object:      session.DomainID,
			ObjectType:  policies.DomainType,
		})
	case domains.EnabledStatus:
		return nil
	default:
		return svcerr.ErrInvalidStatus
	}
}
