// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

import (
	"slices"
	"strings"
	"time"

	apiutil "github.com/absmach/supermq/api/http/util"
	"github.com/absmach/supermq/readers"
)

const maxLimitSize = 1000

var validAggregations = []string{"MAX", "MIN", "AVG", "SUM", "COUNT"}

type readMessagesReq struct {
	chanID   string
	domain   string
	pageMeta readers.PageMetadata
}

func (req readMessagesReq) validate() error {
	if req.chanID == "" {
		return apiutil.ErrMissingID
	}
	if req.domain == "" {
		return apiutil.ErrMissingID
	}

	if req.pageMeta.Limit < 1 || req.pageMeta.Limit > maxLimitSize {
		return apiutil.ErrLimitSize
	}

	if req.pageMeta.Comparator != "" &&
		req.pageMeta.Comparator != readers.EqualKey &&
		req.pageMeta.Comparator != readers.LowerThanKey &&
		req.pageMeta.Comparator != readers.LowerThanEqualKey &&
		req.pageMeta.Comparator != readers.GreaterThanKey &&
		req.pageMeta.Comparator != readers.GreaterThanEqualKey {
		return apiutil.ErrInvalidComparator
	}

	if req.pageMeta.Aggregation == "AGGREGATION_UNSPECIFIED" {
		req.pageMeta.Aggregation = ""
	}

	if agg := strings.ToUpper(req.pageMeta.Aggregation); agg != "" && agg != "AGGREGATION_UNSPECIFIED" {
		if req.pageMeta.From == 0 {
			return apiutil.ErrMissingFrom
		}

		if req.pageMeta.To == 0 {
			return apiutil.ErrMissingTo
		}

		if !slices.Contains(validAggregations, strings.ToUpper(req.pageMeta.Aggregation)) {
			return apiutil.ErrInvalidAggregation
		}

		if _, err := time.ParseDuration(req.pageMeta.Interval); err != nil {
			return apiutil.ErrInvalidInterval
		}
	}

	return nil
}
