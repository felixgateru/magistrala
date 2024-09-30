// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"

	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/pkg/auth"
)

type sessionKeyType string

const SessionKey = sessionKeyType("session")

func AuthenticateMiddleware(authClient auth.AuthClient) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := apiutil.ExtractBearerToken(r)
			if token == "" {
				EncodeError(r.Context(), apiutil.ErrBearerToken, w)
				return
			}

			session, err := authClient.IdentifyAccessToken(r.Context(), token)
			if err != nil {
				EncodeError(r.Context(), err, w)
				return
			}

			ctx := context.WithValue(r.Context(), SessionKey, session)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
