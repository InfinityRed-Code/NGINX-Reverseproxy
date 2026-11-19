// Package apigen enthaelt den aus api/openapi.yaml generierten Server- und Client-Code.
package apigen

//go:generate go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.5.1 -config config.yaml ../../api/openapi.yaml
