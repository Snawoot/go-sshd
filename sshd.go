package main

// Copyright:
// Merlijn B. W. Wajer <merlijn@wizzup.org>
// (C) 2017

// Trivial parts taken from:
// * https://blog.gopheracademy.com/advent-2015/ssh-server-in-go/
// * https://github.com/tg123/sshpiper/commit/9db468b52dfc2cbe936efb7bef0fd5b88e0c1649

import (
	"flag"
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

	listenport     = flag.Int("listenport", 2200, "Port to listen on for incoming ssh connections")
	hostkey        = flag.String("hostkey", "id_rsa", "Server host key to load")
	authorisedkeys = flag.String("authorisedkeys", "authorized_keys", "Authorised keys")
	verbose        = flag.Bool("verbose", false, "Enable verbose mode")
)

func main() {
	flag.Parse()

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

	privateBytes, err := ioutil.ReadFile(*hostkey)
	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)
	loadAuthorisedKeys(*authorisedkeys)

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *listenport))
	if err != nil {
		log.Fatalf("Failed to listen on %s (%s)", listenport, err)
	}

	// Accept all connections
	log.Printf("Listening on %d...", *listenport)
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

		if *verbose {
			log.Printf("Connection from %s (%s). Allowed ports: %s", sshConn.RemoteAddr(), sshConn.ClientVersion(), allowedPorts)
		}

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
	if *verbose {
		log.Println("Channel type:", newChannel.ChannelType())
	}
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
		log.Printf("Tried to forward prohibited port: %d", payload.Port)
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
	if *verbose {
		log.Println("Going to dial:", addr)
	}

	rconn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Could not dial remote (%s)", err)
		connection.Close()
		return
	}

	close := func() {
		connection.Close()
		rconn.Close()
		if *verbose {
			log.Printf("Session closed")
		}
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
	ports := strings.Split(portstr, ":")
	for _, port := range ports {
		port, err := strconv.ParseUint(port, 10, 32)
		if err != nil {
			return p, err
		}
		p = append(p, uint32(port))
	}
	return
}

func loadAuthorisedKeys(authorisedkeys string) {
	authorisedKeys = map[string]string{}
	authorisedKeysBytes, err := ioutil.ReadFile(authorisedkeys)
	if err != nil {
		log.Fatal("Cannot load authorised keys")
	}

	for len(authorisedKeysBytes) > 0 {
		pubkey, _, options, rest, err := ssh.ParseAuthorizedKey(authorisedKeysBytes)

		if err != nil {
			log.Fatal(err)
		}

		log.Println("Options:", options)
		if len(options) != 1 {
			log.Fatal(fmt.Errorf("Only one option is accepted: 'ports=...'"))
		}

		option := options[0]

		if !strings.HasPrefix(option, "ports=") {
			log.Fatal(fmt.Errorf("Options does not start with 'ports='"))
		}

		ports := option[len("ports="):]

		_, err = parsePorts(ports)

		if err != nil {
			log.Fatal(err)
		}

		authorisedKeys[string(pubkey.Marshal())] = ports
		authorisedKeysBytes = rest
	}
}
