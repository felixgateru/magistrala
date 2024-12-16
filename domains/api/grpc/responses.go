// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package grpc

type deleteUserRes struct {
	deleted bool
}

type retrieveEntityRes struct {
	id     string
	name   string
	status uint8
}
