package smp

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rigado/ble"
	"github.com/rigado/ble/linux/hci"
)

var errStale = errors.New("stale result from a previous attempt")

var testSmpConfig = hci.SmpConfig{
	IoCap:       hci.IoCapsKeyboardDisplay,
	OobFlag:     byte(hci.OobNotPresent),
	AuthReq:     0x0D, // bond | MITM | secure connections
	MaxKeySize:  16,
	InitKeyDist: 0x00,
	RespKeyDist: 0x01,
}

// A pairing response that selects Passkey Entry: DisplayOnly peer with
// MITM and secure connections set.
var passkeyPairingRsp = []byte{hci.IoCapsDisplayOnly, 0x00, 0x0D, 16, 0x00, 0x01}

func newTestTransport(authData ble.AuthData) *transport {
	p := &pairingContext{
		request:  testSmpConfig,
		state:    Init,
		authData: authData,
		Logger:   ble.GetLogger(),
	}
	return &transport{
		pairing:  p,
		writePDU: func(b []byte) (int, error) { return len(b), nil },
		Logger:   ble.GetLogger(),
	}
}

// Passkey pairing without a passkey source must abort instead of running
// the protocol with a bogus passkey of 0. This matters for pairing
// triggered by a peripheral security request before Pair() supplied auth
// data.
func TestPairingResponsePasskeyWithoutSource(t *testing.T) {
	tran := newTestTransport(ble.AuthData{})

	_, err := smpOnPairingResponse(tran, passkeyPairingRsp)
	if err == nil || !strings.Contains(err.Error(), "requires a passkey") {
		t.Fatalf("got err %v, want passkey source error", err)
	}
	if tran.pairing.state != Error {
		t.Fatalf("state = %v, want Error", tran.pairing.state)
	}
}

func TestPairingResponsePasskeyWithSource(t *testing.T) {
	tran := newTestTransport(ble.AuthData{
		PasskeyFn: func() (int, error) { return 123456, nil },
	})

	if _, err := smpOnPairingResponse(tran, passkeyPairingRsp); err != nil {
		t.Fatalf("smpOnPairingResponse: %v", err)
	}
	if tran.pairing.pairingType != Passkey {
		t.Fatalf("pairingType = %v, want Passkey", tran.pairing.pairingType)
	}
	if tran.pairing.state != WaitPublicKey {
		t.Fatalf("state = %v, want WaitPublicKey", tran.pairing.state)
	}
}

// deliverResult must never block the caller, even with nobody waiting for
// the result: it is called from the connection's read loop.
func TestDeliverResultNeverBlocks(t *testing.T) {
	m := NewSmpManager(testSmpConfig, nil, ble.GetLogger())

	done := make(chan struct{})
	go func() {
		m.deliverResult(nil)
		m.deliverResult(nil)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deliverResult blocked with no waiter")
	}
}

// Pair must be able to start over after a previous attempt failed, e.g.
// one auto-triggered by a peripheral security request.
func TestPairResetsAfterError(t *testing.T) {
	m := NewSmpManager(testSmpConfig, nil, ble.GetLogger())
	wrote := make(chan []byte, 4)
	m.SetWritePDUFunc(func(b []byte) (int, error) {
		wrote <- b
		return len(b), nil
	})
	m.InitContext(
		[]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		[]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		0x00, 0x00)

	// Simulate a failed earlier attempt, with a stale unread result.
	m.pairing.state = Error
	m.deliverResult(errStale)

	pairDone := make(chan error, 1)
	go func() {
		pairDone <- m.Pair(ble.AuthData{Passkey: 123456}, time.Minute)
	}()

	// Pairing request must go out on the wire again.
	select {
	case pdu := <-wrote:
		// L2CAP header (4 bytes), then the SMP pairing request opcode.
		if len(pdu) < 5 || pdu[4] != pairingRequest {
			t.Fatalf("unexpected PDU written: %x", pdu)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Pair did not send a pairing request after an earlier failure")
	}

	// Complete the attempt; Pair must return this attempt's result, not
	// the stale one.
	m.deliverResult(nil)
	select {
	case err := <-pairDone:
		if err != nil {
			t.Fatalf("Pair: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Pair did not return")
	}
}

func TestPairWhileInProgress(t *testing.T) {
	m := NewSmpManager(testSmpConfig, nil, ble.GetLogger())
	m.SetWritePDUFunc(func(b []byte) (int, error) { return len(b), nil })
	m.pairing.state = WaitPublicKey

	err := m.Pair(ble.AuthData{Passkey: 123456}, time.Minute)
	if err == nil || !strings.Contains(err.Error(), "already in progress") {
		t.Fatalf("got err %v, want already-in-progress error", err)
	}
}
