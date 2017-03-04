package main

// Copyright:
// Merlijn B. W. Wajer <merlijn@wizzup.org>
// (C) 2017

// Trivial parts taken from:
// * https://blog.gopheracademy.com/advent-2015/ssh-server-in-go/
// * https://github.com/tg123/sshpiper/commit/9db468b52dfc2cbe936efb7bef0fd5b88e0c1649

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

var (
	authorisedKeys map[string]string
)

func main() {
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if ports, found := authorisedKeys[string(key.Marshal())]; found {
				return &ssh.Permissions{
					CriticalOptions: map[string]string{"ports": ports},
				}, nil
			}

			return nil, fmt.Errorf("Unknown public key\n")
		},
	}

	privateBytes, err := ioutil.ReadFile("id_ed25519")
	//privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)
	loadKeys()

	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		log.Fatalf("Failed to listen on 2200 (%s)", err)
	}

	// Accept all connections
	log.Print("Listening on 2200...")
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}
		// Before use, a handshake must be performed on the incoming net.Conn.
		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
		if err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		allowedPorts := sshConn.Permissions.CriticalOptions["ports"]

		log.Printf("Connection from %s (%s). Allowed ports: %s", sshConn.RemoteAddr(), sshConn.ClientVersion(), allowedPorts)

		// Parsing a second time should not error
		ports, _ := parsePorts(allowedPorts)

		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(reqs)
		// Accept all channels
		go handleChannels(chans, ports)
	}
}

func handleChannels(chans <-chan ssh.NewChannel, ports []uint32) {
	for c := range chans {
		go handleChannel(c, ports)
	}
}

/* RFC4254 7.2 */
type directTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

func handleChannel(newChannel ssh.NewChannel, ports []uint32) {
	log.Println("Channel type:", newChannel.ChannelType())
	if t := newChannel.ChannelType(); t != "direct-tcpip" {
		newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Only \"direct-tcpip\" is accepted"))
		return
	}

	var payload directTCPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		log.Printf("Could not unmarshal extra data: %s\n", err)

		newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Bad payload"))
		return
	}

	//log.Println("Got payload: %v", payload)
	if payload.Addr != "localhost" {
		newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Bad addr"))
		return
	}

	ok := false
	for _, port := range ports {
		if payload.Port == port {
			ok = true
			break
		}
	}

	if !ok {
		newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Bad port"))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	_ = requests // TODO: Think we can just ignore these
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}

	addr := fmt.Sprintf("%s:%d", payload.Addr, payload.Port)
	log.Println("Going to dial:", addr)

	rconn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Could not dial remote (%s)", err)
		connection.Close()
		return
	}

	close := func() {
		connection.Close()
		rconn.Close()
		log.Printf("Session closed")
	}

	var once sync.Once
	go func() {
		io.Copy(connection, rconn)
		once.Do(close)
	}()
	go func() {
		io.Copy(rconn, connection)
		once.Do(close)
	}()
}

func parsePorts(portstr string) (p []uint32, err error) {
	ports := strings.Split(portstr, ",")
	for _, port := range ports {
		port, err := strconv.ParseUint(port, 10, 32)
		if err != nil {
			return p, err
		}
		p = append(p, uint32(port))
	}
	return
}

func loadKeys() {
	authorisedKeys = map[string]string{}
	authorisedKeysBytes, err := ioutil.ReadFile("authorized_keys")
	if err != nil {
		log.Fatal("Cannot load authorised keys")
	}

	for len(authorisedKeysBytes) > 0 {
		pubkey, ports, _, rest, err := ssh.ParseAuthorizedKey(authorisedKeysBytes)

		if err != nil {
			log.Fatal(err)
		}

		_, err = parsePorts(ports)

		if err != nil {
			log.Fatal(err)
		}

		authorisedKeys[string(pubkey.Marshal())] = ports
		authorisedKeysBytes = rest
	}
}
