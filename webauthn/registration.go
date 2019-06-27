package webauthn

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"net/http"

	"github.com/koesie10/webauthn/protocol"
)

func b2s(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}
func s2b(data string) ([]byte, bool) {
	by, err := base64.URLEncoding.DecodeString(data)
	if err != nil {
		log.Printf("s2b error: %v", data)
		return nil, false
	}
	return by, true
}

// GetRegistrationOptions will return the options that need to be passed to navigator.credentials.create(). This should
// be returned to the user via e.g. JSON over HTTP. For convenience, use StartRegistration.
func (w *WebAuthn) GetRegistrationOptions(user User, session Session) (*protocol.CredentialCreationOptions, error) {
	chal, err := protocol.NewChallenge()
	if err != nil {
		return nil, err
	}

	u := protocol.PublicKeyCredentialUserEntity{
		ID: user.WebAuthID(),
		PublicKeyCredentialEntity: protocol.PublicKeyCredentialEntity{
			Name: user.WebAuthName(),
		},
		DisplayName: user.WebAuthDisplayName(),
	}

	options := &protocol.CredentialCreationOptions{
		PublicKey: protocol.PublicKeyCredentialCreationOptions{
			Challenge: chal,
			RP: protocol.PublicKeyCredentialRpEntity{
				ID: w.Config.RelyingPartyID,
				PublicKeyCredentialEntity: protocol.PublicKeyCredentialEntity{
					Name: w.Config.RelyingPartyName,
				},
			},
			PubKeyCredParams: []protocol.PublicKeyCredentialParameters{
				{
					Type:      protocol.PublicKeyCredentialTypePublicKey,
					Algorithm: protocol.ES256,
				},
			},
			Timeout:     w.Config.Timeout,
			User:        u,
			Attestation: protocol.AttestationConveyancePreferenceDirect,
		},
	}

	authenticators, err := w.Config.AuthenticatorStore.GetAuthenticators(user)
	if err != nil {
		return nil, err
	}

	excludeCredentials := make([]protocol.PublicKeyCredentialDescriptor, len(authenticators))

	for i, authr := range authenticators {
		excludeCredentials[i] = protocol.PublicKeyCredentialDescriptor{
			ID:   authr.WebAuthCredentialID(),
			Type: protocol.PublicKeyCredentialTypePublicKey,
		}
	}

	options.PublicKey.ExcludeCredentials = excludeCredentials

	if err := session.Set(w.Config.SessionKeyPrefixChallenge+".register", b2s([]byte(chal))); err != nil {
		return nil, err
	}
	if err := session.Set(w.Config.SessionKeyPrefixUserID+".register", b2s(u.ID)); err != nil {
		return nil, err
	}

	return options, nil
}

// StartRegistration is a HTTP request handler which writes the options to be passed to navigator.credentials.create()
// to the http.ResponseWriter.
func (w *WebAuthn) StartRegistration(r *http.Request, rw http.ResponseWriter, user User, session Session) {
	options, err := w.GetRegistrationOptions(user, session)
	if err != nil {
		w.writeError(r, rw, err)
		return
	}

	w.write(r, rw, options)
}

// ParseAndFinishRegistration should receive the response of navigator.credentials.create(). If
// the request is valid, AuthenticatorStore.AddAuthenticator will be called and the authenticator that was registered
// will be returned. For convenience, use FinishRegistration.
func (w *WebAuthn) ParseAndFinishRegistration(attestationResponse protocol.AttestationResponse, user User, session Session) (Authenticator, error) {
	rawChal, err := session.Get(w.Config.SessionKeyPrefixChallenge + ".register")
	if err != nil {
		log.Printf("xx 2 1")
		return nil, protocol.ErrInvalidRequest.WithDebug("missing challenge in session")
	}
	chal, ok := s2b(rawChal) //rawChal.([]byte)
	if !ok {
		log.Printf("xx 2 2")
		return nil, protocol.ErrInvalidRequest.WithDebug("invalid challenge session value")
	}
	if err := session.Delete(w.Config.SessionKeyPrefixChallenge + ".register"); err != nil {

		log.Printf("xx 2 3")
		return nil, err
	}

	rawUserID, err := session.Get(w.Config.SessionKeyPrefixUserID + ".register")
	if err != nil {
		log.Printf("xx 2 4")
		return nil, protocol.ErrInvalidRequest.WithDebug("missing user ID in session")
	}
	userID, ok := s2b(rawUserID) //rawUserID.([]byte)
	if !ok {
		log.Printf("xx 2 5")
		return nil, protocol.ErrInvalidRequest.WithDebug("invalid user ID session value")
	}
	if err := session.Delete(w.Config.SessionKeyPrefixUserID + ".register"); err != nil {

		log.Printf("xx 2 6")
		return nil, err
	}

	if !bytes.Equal(user.WebAuthID(), userID) {

		log.Printf("xx 2 7")
		return nil, protocol.ErrInvalidRequest.WithDebug("user has changed since start of registration")
	}

	p, err := protocol.ParseAttestationResponse(attestationResponse)
	if err != nil {

		log.Printf("xx 2 8")
		return nil, err
	}

	valid, err := protocol.IsValidAttestation(p, chal, w.Config.RelyingPartyID, w.Config.RelyingPartyOrigin)
	if err != nil {

		log.Printf("xx 2 9")
		return nil, err
	}

	if !valid {
		log.Printf("xx 2 10")
		return nil, protocol.ErrInvalidRequest.WithDebug("invalid registration")
	}

	data, err := x509.MarshalPKIXPublicKey(p.Response.Attestation.AuthData.AttestedCredentialData.COSEKey)
	if err != nil {
		log.Printf("xx 2 11")
		return nil, err
	}

	authr := &defaultAuthenticator{
		id:           p.RawID,
		credentialID: p.Response.Attestation.AuthData.AttestedCredentialData.CredentialID,
		publicKey: pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: data,
		}),
		aaguid:    p.Response.Attestation.AuthData.AttestedCredentialData.AAGUID,
		signCount: p.Response.Attestation.AuthData.SignCount,
	}

	if err := w.Config.AuthenticatorStore.AddAuthenticator(user, authr); err != nil {

		log.Printf("xx 2 12")
		return nil, err
	}

	return authr, nil
}

// FinishRegistration is a HTTP request handler which should receive the response of navigator.credentials.create(). If
// the request is valid, AuthenticatorStore.AddAuthenticator will be called and an empty response with HTTP status code
// 201 (Created) will be written to the http.ResponseWriter. If authenticator is  nil, an error has been written to
// http.ResponseWriter and should be returned as-is.
func (w *WebAuthn) FinishRegistration(r *http.Request, rw http.ResponseWriter, user User, session Session) Authenticator {
	var attestationResponse protocol.AttestationResponse
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&attestationResponse); err != nil {
		log.Printf("xx 1")
		w.writeError(r, rw, protocol.ErrInvalidRequest.WithDebug(err.Error()))
		return nil
	}

	authr, err := w.ParseAndFinishRegistration(attestationResponse, user, session)
	if err != nil {
		log.Printf("xx 2")
		w.writeError(r, rw, err)
		return nil
	}

	log.Printf("xx 3")
	rw.WriteHeader(http.StatusCreated)

	return authr
}
