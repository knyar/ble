package ble

type AuthData struct {
	// Passkey is the numeric passkey for pairing.
	Passkey int

	// PasskeyFn is a function that returns the passkey for pairing.
	// If Passkey is not set, this function will be called (at most once)
	// to retrieve the passkey. Returning an error aborts the pairing
	// attempt.
	PasskeyFn func() (int, error)

	// OOBData is the out-of-band data for pairing.
	OOBData []byte

	// resolved reports whether PasskeyFn has already been invoked;
	// its outcome (including a returned error) is cached so that the
	// user is not prompted again for the same pairing attempt.
	resolved   bool
	passkeyErr error
}

// HasPasskeySource reports whether a passkey is available for pairing,
// either directly or via PasskeyFn.
func (a *AuthData) HasPasskeySource() bool {
	return a.Passkey != 0 || a.PasskeyFn != nil
}

// GetPasskey returns the passkey for pairing. If Passkey is not set,
// it calls PasskeyFn (once) to populate it.
func (a *AuthData) GetPasskey() (int, error) {
	if a.Passkey != 0 || a.PasskeyFn == nil {
		return a.Passkey, nil
	}
	if !a.resolved {
		a.resolved = true
		a.Passkey, a.passkeyErr = a.PasskeyFn()
	}
	return a.Passkey, a.passkeyErr
}
