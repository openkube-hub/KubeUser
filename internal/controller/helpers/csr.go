/*
Copyright 2026.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
*/

package helpers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// VerifyCSRMatchesKey confirms that csrPEM was generated from keyPEM by
// comparing the RSA public keys. This is the anti-impersonation check: any
// pre-existing CSR under the operator's deterministic name whose public key
// does not match the operator's stored private key must be discarded before
// approval — otherwise an attacker with `create` on CSRs could pre-plant a
// request under our name and receive a signed cert bound to their own key.
func VerifyCSRMatchesKey(csrPEM, keyPEM []byte) error {
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return errors.New("invalid CSR PEM")
	}
	csrReq, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CSR: %w", err)
	}
	csrPub, ok := csrReq.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("unexpected CSR public key type %T (want *rsa.PublicKey)", csrReq.PublicKey)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("invalid private key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	if !csrPub.Equal(&key.PublicKey) {
		return errors.New("CSR public key does not match operator-held private key")
	}
	return nil
}
