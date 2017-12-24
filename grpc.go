package curvetls

import (
	"context"
	"net"

	"google.golang.org/grpc/credentials"
)

// NewGRPCCredentials returns a curvetls implementation of gRPC's credentials.TransportCredentials
func NewGRPCCredentials(pubKey Pubkey, privKey Privkey) GRPCCredentials {
	return GRPCCredentials{
		Pub:  pubKey,
		Priv: privKey,
	}
}

// GRPCCredentials implements credentials.TransportCredentials
type GRPCCredentials struct {
	Pub  Pubkey
	Priv Privkey
}

type authInfo struct{}

func (a authInfo) AuthType() string {
	return "curvetls"
}

// ServerHandshake ...
func (g *GRPCCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {

	longNonce, err := NewLongNonce()
	if err != nil {
		return nil, nil, err
	}

	myNonce := newShortNonce()
	clientNonce := newShortNonce()

	var mygreeting, theirgreeting, expectedgreeting greeting
	mygreeting.asServer()
	expectedgreeting.asClient()

	if err := wrc(rawConn, mygreeting[:], theirgreeting[:]); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	if theirgreeting != expectedgreeting {
		return nil, nil, closeAndBail(rawConn, newProtocolError("malformed greeting"))
	}

	var helloCmd helloCommand
	if err := readFrame(rawConn, &helloCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	ephClientPubkey, err := helloCmd.validate(clientNonce, permanentServerPrivkey(g.Priv))
	if err != nil {
		return nil, nil, pE(rawConn, "HELLO", err)
	}

	var welcomeCmd welcomeCommand
	cookieKey, err := welcomeCmd.build(longNonce, ephClientPubkey, permanentServerPrivkey(g.Priv))
	if err != nil {
		return nil, nil, iE(rawConn, "WELCOME", err)
	}
	if err := writeFrame(rawConn, &welcomeCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	var initiateCmd initiateCommand
	if err := readFrame(rawConn, &initiateCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	_, ephClientPubkey, ephServerPrivkey, err := initiateCmd.validate(
		clientNonce, permanentServerPubkey(g.Pub), cookieKey)
	if err != nil {
		return nil, nil, pE(rawConn, "INITIATE", err)
	}
	auth := &Authorizer{&EncryptedConn{
		Conn:       rawConn,
		myNonce:    myNonce,
		theirNonce: clientNonce,
		sharedKey:  precomputeKey(Privkey(ephServerPrivkey), Pubkey(ephClientPubkey)),
		isServer:   true,
	}}

	encrypted, err := auth.Allow()
	if err != nil {
		// close rawConn here?
		return nil, nil, closeAndBail(encrypted, err)
	}

	return encrypted, authInfo{}, nil
}

func (g *GRPCCredentials) ClientHandshake(ctx context.Context, s string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {

	return nil, nil, nil
}

func (g *GRPCCredentials) Info() credentials.ProtocolInfo {

	return credentials.ProtocolInfo{}
}

func (g *GRPCCredentials) Clone() credentials.TransportCredentials {

	return nil
}

func (g *GRPCCredentials) OverrideServerName(string) error {
	return nil
}

// type TransportCredentials interface {
// 	// ClientHandshake does the authentication handshake specified by the corresponding
// 	// authentication protocol on rawConn for clients. It returns the authenticated
// 	// connection and the corresponding auth information about the connection.
// 	// Implementations must use the provided context to implement timely cancellation.
// 	// gRPC will try to reconnect if the error returned is a temporary error
// 	// (io.EOF, context.DeadlineExceeded or err.Temporary() == true).
// 	// If the returned error is a wrapper error, implementations should make sure that
// 	// the error implements Temporary() to have the correct retry behaviors.
// 	//
// 	// If the returned net.Conn is closed, it MUST close the net.Conn provided.
// 	ClientHandshake(context.Context, string, net.Conn) (net.Conn, AuthInfo, error)
// 	// ServerHandshake does the authentication handshake for servers. It returns
// 	// the authenticated connection and the corresponding auth information about
// 	// the connection.
// 	//
// 	// If the returned net.Conn is closed, it MUST close the net.Conn provided.
// 	ServerHandshake(net.Conn) (net.Conn, AuthInfo, error)
// 	// Info provides the ProtocolInfo of this TransportCredentials.
// 	Info() ProtocolInfo
// 	// Clone makes a copy of this TransportCredentials.
// 	Clone() TransportCredentials
// 	// OverrideServerName overrides the server name used to verify the hostname on the returned certificates from the server.
// 	// gRPC internals also use it to override the virtual hosting name if it is set.
// 	// It must be called before dialing. Currently, this is only used by grpclb.
// 	OverrideServerName(string) error
// }
