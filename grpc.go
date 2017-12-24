package curvetls

import (
	"context"
	"net"

	"google.golang.org/grpc/credentials"
)

// NewGRPCServerCredentials returns a curvetls implementation of gRPC's credentials.TransportCredentials
func NewGRPCServerCredentials(pubKey Pubkey, privKey Privkey) GRPCCredentials {
	return GRPCCredentials{
		Pub:  pubKey,
		Priv: privKey,
	}
}

func NewGRPCClientCredentials(serverPubKey, pubKey Pubkey, privKey Privkey) credentials.TransportCredentials {
	return &GRPCCredentials{
		Pub:        serverPubKey,
		ClientPub:  pubKey,
		ClientPriv: privKey,
	}
}

// GRPCCredentials implements credentials.TransportCredentials
type GRPCCredentials struct {
	Pub        Pubkey
	Priv       Privkey
	ClientPub  Pubkey
	ClientPriv Privkey
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

// ClientHandshake ...
func (g *GRPCCredentials) ClientHandshake(ctx context.Context, s string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {

	longNonce, err := NewLongNonce()
	if err != nil {
		return nil, nil, err
	}

	myNonce := newShortNonce()
	serverNonce := newShortNonce()

	ephClientPrivkey, ephClientPubkey, err := genEphemeralClientKeyPair()
	if err != nil {
		return nil, nil, closeAndBail(rawConn, newInternalError("cannot generate ephemeral keypair", err))
	}

	var mygreeting, theirgreeting, expectedgreeting greeting
	mygreeting.asClient()
	expectedgreeting.asServer()

	if err := wrc(rawConn, mygreeting[:], theirgreeting[:]); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	if theirgreeting != expectedgreeting {
		return nil, nil, closeAndBail(rawConn, newProtocolError("malformed greeting"))
	}

	var helloCmd helloCommand
	if err := helloCmd.build(myNonce, ephClientPrivkey, ephClientPubkey, permanentServerPubkey(g.Pub)); err != nil {
		return nil, nil, iE(rawConn, "HELLO", err)
	}

	if err := writeFrame(rawConn, &helloCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	var welcomeCmd welcomeCommand
	if err := readFrame(rawConn, &welcomeCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	ephServerPubkey, sCookie, err := welcomeCmd.validate(ephClientPrivkey, permanentServerPubkey(g.Pub))
	if err != nil {
		return nil, nil, pE(rawConn, "WELCOME", err)
	}

	var initiateCmd initiateCommand
	if err := initiateCmd.build(myNonce,
		longNonce,
		sCookie,
		permanentClientPrivkey(g.ClientPriv),
		permanentClientPubkey(g.ClientPub),
		permanentServerPubkey(g.Pub),
		ephServerPubkey,
		ephClientPrivkey,
		ephClientPubkey); err != nil {
		return nil, nil, iE(rawConn, "INITIATE", err)
	}

	if err := writeFrame(rawConn, &initiateCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	var genericCmd genericCommand
	if err := readFrame(rawConn, &genericCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	specificCmd, err := genericCmd.convert()
	if err != nil {
		return nil, nil, pE(rawConn, "READY or ERROR", err)
	}

	sharedKey := precomputeKey(Privkey(ephClientPrivkey), Pubkey(ephServerPubkey))

	switch cmd := specificCmd.(type) {
	case *readyCommand:
		if err := cmd.validate(serverNonce, &sharedKey); err != nil {
			return nil, nil, pE(rawConn, "READY", err)
		}
	case *errorCommand:
		reason, err := cmd.validate()
		if err != nil {
			return nil, nil, pE(rawConn, "ERROR", err)
		}
		return nil, nil, closeAndBail(rawConn, newAuthenticationError(reason))
	default:
		return nil, nil, pE(rawConn, "unknown command", err)
	}

	return &EncryptedConn{
		Conn:       rawConn,
		myNonce:    myNonce,
		theirNonce: serverNonce,
		sharedKey:  sharedKey,
		isServer:   false,
	}, nil, nil
}

// Info ...
func (g *GRPCCredentials) Info() credentials.ProtocolInfo {

	return credentials.ProtocolInfo{}
}

func (g *GRPCCredentials) Clone() credentials.TransportCredentials {

	return &GRPCCredentials{
		Pub:        g.Pub,
		Priv:       g.Priv,
		ClientPub:  g.ClientPub,
		ClientPriv: g.ClientPriv,
	}
}

func (g *GRPCCredentials) OverrideServerName(string) error {
	// TODO
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
