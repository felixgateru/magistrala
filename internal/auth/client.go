// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/absmach/magistrala"
	mgauth "github.com/absmach/magistrala/auth"
	"github.com/absmach/magistrala/pkg/auth"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	"github.com/go-kit/kit/endpoint"
	kitgrpc "github.com/go-kit/kit/transport/grpc"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	authzSvcName  = "magistrala.AuthzService"
	authnSvcName  = "magistrala.AuthnService"
	issuerName    = "magistrala.auth"
	cacheDuration = 5 * time.Minute
)

var (
	// errJWTExpiryKey is used to check if the token is expired.
	errJWTExpiryKey = errors.New(`"exp" not satisfied`)
	// errInvalidIssuer indicates an invalid issuer value.
	errInvalidIssuer = errors.New("invalid token issuer value")
	// ErrValidateJWTToken indicates a failure to validate JWT token.
	ErrValidateJWTToken = errors.New("failed to validate jwt token")

	jwksCache = struct {
		jwks     mgauth.JWKS
		cachedAt time.Time
	}{}
)

type authGrpcClient struct {
	issue     endpoint.Endpoint
	refresh   endpoint.Endpoint
	authorize endpoint.Endpoint
	identify  endpoint.Endpoint
	timeout   time.Duration
	jwksURL   string
}

// NewAuthClient returns new auth gRPC client instance.
func NewAuthClient(conn *grpc.ClientConn, timeout time.Duration, jwksURL string) auth.AuthClient {
	return &authGrpcClient{
		issue: kitgrpc.NewClient(
			conn,
			authnSvcName,
			"Issue",
			encodeIssueRequest,
			decodeIssueResponse,
			magistrala.Token{},
		).Endpoint(),
		refresh: kitgrpc.NewClient(
			conn,
			authnSvcName,
			"Refresh",
			encodeRefreshRequest,
			decodeRefreshResponse,
			magistrala.Token{},
		).Endpoint(),
		identify: kitgrpc.NewClient(
			conn,
			authnSvcName,
			"Identify",
			encodeIdentifyRequest,
			decodeIdentifyResponse,
			magistrala.IdentityRes{},
		).Endpoint(),
		authorize: kitgrpc.NewClient(
			conn,
			authzSvcName,
			"Authorize",
			encodeAuthorizeRequest,
			decodeAuthorizeResponse,
			magistrala.AuthorizeRes{},
		).Endpoint(),
		timeout: timeout,
		jwksURL: jwksURL,
	}
}

func (client authGrpcClient) Issue(ctx context.Context, req *magistrala.IssueReq, _ ...grpc.CallOption) (*magistrala.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.issue(ctx, issueReq{
		userID:   req.GetUserId(),
		domainID: req.GetDomainId(),
		keyType:  mgauth.KeyType(req.GetType()),
	})
	if err != nil {
		return &magistrala.Token{}, decodeError(err)
	}
	return res.(*magistrala.Token), nil
}

func encodeIssueRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(issueReq)
	return &magistrala.IssueReq{
		UserId:   req.userID,
		DomainId: &req.domainID,
		Type:     uint32(req.keyType),
	}, nil
}

func decodeIssueResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	return grpcRes, nil
}

func (client authGrpcClient) Refresh(ctx context.Context, req *magistrala.RefreshReq, _ ...grpc.CallOption) (*magistrala.Token, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.refresh(ctx, refreshReq{refreshToken: req.GetRefreshToken(), domainID: req.GetDomainId()})
	if err != nil {
		return &magistrala.Token{}, decodeError(err)
	}
	return res.(*magistrala.Token), nil
}

func encodeRefreshRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(refreshReq)
	return &magistrala.RefreshReq{RefreshToken: req.refreshToken, DomainId: &req.domainID}, nil
}

func decodeRefreshResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	return grpcRes, nil
}

func (client authGrpcClient) Identify(ctx context.Context, token *magistrala.IdentityReq, _ ...grpc.CallOption) (*magistrala.IdentityRes, error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.identify(ctx, identityReq{token: token.GetToken()})
	if err != nil {
		return &magistrala.IdentityRes{}, decodeError(err)
	}
	ir := res.(identityRes)
	return &magistrala.IdentityRes{Id: ir.subject, UserId: ir.userID, DomainId: ir.domainID}, nil
}

func encodeIdentifyRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(identityReq)
	return &magistrala.IdentityReq{Token: req.token}, nil
}

func decodeIdentifyResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.IdentityRes)
	return identityRes{subject: res.GetId(), userID: res.GetUserId(), domainID: res.GetDomainId()}, nil
}

func (client authGrpcClient) Authorize(ctx context.Context, req *magistrala.AuthorizeReq, _ ...grpc.CallOption) (r *magistrala.AuthorizeRes, err error) {
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()

	res, err := client.authorize(ctx, authReq{
		Domain:      req.GetDomain(),
		SubjectType: req.GetSubjectType(),
		Subject:     req.GetSubject(),
		SubjectKind: req.GetSubjectKind(),
		Relation:    req.GetRelation(),
		Permission:  req.GetPermission(),
		ObjectType:  req.GetObjectType(),
		Object:      req.GetObject(),
	})
	if err != nil {
		return &magistrala.AuthorizeRes{}, decodeError(err)
	}

	ar := res.(authorizeRes)
	return &magistrala.AuthorizeRes{Authorized: ar.authorized, Id: ar.userID}, nil
}

func decodeAuthorizeResponse(_ context.Context, grpcRes interface{}) (interface{}, error) {
	res := grpcRes.(*magistrala.AuthorizeRes)
	return authorizeRes{authorized: res.Authorized, userID: res.Id}, nil
}

func encodeAuthorizeRequest(_ context.Context, grpcReq interface{}) (interface{}, error) {
	req := grpcReq.(authReq)
	return &magistrala.AuthorizeReq{
		Domain:      req.Domain,
		SubjectType: req.SubjectType,
		Subject:     req.Subject,
		SubjectKind: req.SubjectKind,
		Relation:    req.Relation,
		Permission:  req.Permission,
		ObjectType:  req.ObjectType,
		Object:      req.Object,
	}, nil
}

func (client authGrpcClient) ParseToken(ctx context.Context, token string) (auth.Session, error) {
	jwks, err := client.fetchJWKS()
	if err != nil {
		return auth.Session{}, err
	}

	publicKey, err := createPublicKey(jwks.Keys[0])
	if err != nil {
		return auth.Session{}, err
	}

	tkn, err := validateToken(token, publicKey)
	if err != nil {
		return auth.Session{}, err
	}

	res := auth.Session{DomainUserID: tkn.Subject()}
	pc := tkn.PrivateClaims()
	if pc["user"] != nil {
		res.UserID = pc["user"].(string)
	}
	if pc["domain"] != nil {
		res.DomainID = pc["domain"].(string)
	}

	return res, nil

}

func (client authGrpcClient) fetchJWKS() (mgauth.JWKS, error) {
	req, err := http.NewRequest("GET", client.jwksURL, nil)
	if err != nil {
		return mgauth.JWKS{}, err
	}
	req.Header.Set("Accept", "application/json")

	httpClient := &http.Client{}
	if time.Since(jwksCache.cachedAt) < cacheDuration && jwksCache.jwks.Keys != nil {
		return jwksCache.jwks, nil
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return mgauth.JWKS{}, err
	}
	defer resp.Body.Close()

	var jwks mgauth.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return mgauth.JWKS{}, err
	}
	jwksCache.jwks = jwks
	jwksCache.cachedAt = time.Now()

	return jwks, nil
}

func validateToken(token string, publicKey *rsa.PublicKey) (jwt.Token, error) {
	tkn, err := jwt.Parse(
		[]byte(token),
		jwt.WithValidate(true),
		jwt.WithKey(jwa.RS256, publicKey),
	)
	if err != nil {
		if errors.Contains(err, errJWTExpiryKey) {
			return nil, mgauth.ErrExpiry
		}

		return nil, err
	}
	validator := jwt.ValidatorFunc(func(_ context.Context, t jwt.Token) jwt.ValidationError {
		if t.Issuer() != issuerName {
			return jwt.NewValidationError(errInvalidIssuer)
		}
		return nil
	})
	if err := jwt.Validate(tkn, jwt.WithValidator(validator)); err != nil {
		return nil, errors.Wrap(ErrValidateJWTToken, err)
	}

	return tkn, nil
}

func createPublicKey(jwk mgauth.JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	publicKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	return publicKey, nil
}

func decodeError(err error) error {
	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			return errors.Wrap(svcerr.ErrNotFound, errors.New(st.Message()))
		case codes.InvalidArgument:
			return errors.Wrap(errors.ErrMalformedEntity, errors.New(st.Message()))
		case codes.AlreadyExists:
			return errors.Wrap(svcerr.ErrConflict, errors.New(st.Message()))
		case codes.Unauthenticated:
			return errors.Wrap(svcerr.ErrAuthentication, errors.New(st.Message()))
		case codes.OK:
			if msg := st.Message(); msg != "" {
				return errors.Wrap(errors.ErrUnidentified, errors.New(msg))
			}
			return nil
		case codes.FailedPrecondition:
			return errors.Wrap(errors.ErrMalformedEntity, errors.New(st.Message()))
		case codes.PermissionDenied:
			return errors.Wrap(svcerr.ErrAuthorization, errors.New(st.Message()))
		default:
			return errors.Wrap(fmt.Errorf("unexpected gRPC status: %s (status code:%v)", st.Code().String(), st.Code()), errors.New(st.Message()))
		}
	}
	return err
}

type identityRes struct {
	subject  string
	userID   string
	domainID string
}

type authorizeRes struct {
	userID     string
	authorized bool
}
