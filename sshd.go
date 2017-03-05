package main

// Copyright:
// Merlijn B. W. Wajer <merlijn@wizzup.org>
// (C) 2017

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

	/* Global listeners, we keep a global state for cancel-tcpip-forward */
	globalListens map[string]net.Listener

	listenport     = flag.Int("listenport", 2200, "Port to listen on for incoming ssh connections")
	hostkey        = flag.String("hostkey", "id_rsa", "Server host key to load")
	authorisedkeys = flag.String("authorisedkeys", "authorized_keys", "Authorised keys")
	verbose        = flag.Bool("verbose", false, "Enable verbose mode")
)

/* RFC4254 7.2 */
type directTCPPayload struct {
	Addr       string // To connect to
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type forwardedTCPPayload struct {
	Addr       string // Is connected to
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

type tcpIpForwardPayload struct {
	Addr string
	Port uint32
}

type tcpIpForwardPayloadReply struct {
	Port uint32
}

type tcpIpForwardCancelPayload struct {
	Addr string
	Port uint32
}

func main() {
	flag.Parse()

	globalListens = make(map[string]net.Listener)

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

	loadHostKeys(config)
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

		// Parsing a second time should not error, so we can ignore the error
		// safely
		ports, _ := parsePorts(allowedPorts)

		// Handle global out-of-band Requests
		go func() {
			for req := range reqs {
				if *verbose {
					log.Println("Out of band request:", req.Type, req.WantReply)
				}

				// RFC4254: 7.1 for forwarding
				if req.Type == "tcpip-forward" {
					handleTcpIpForward(sshConn, req)
					continue
				} else if req.Type == "cancel-tcpip-forward" {
					handleTcpIPForwardCancel(req)
					continue
				} else {
					// Discard everything else
					req.Reply(false, []byte{})
				}
			}
		}()

		// Accept all channels
		go handleChannels(chans, ports)
	}
}

func handleChannels(chans <-chan ssh.NewChannel, ports []uint32) {
	for c := range chans {
		go handleChannel(c, ports)
	}
}

func handleChannel(newChannel ssh.NewChannel, ports []uint32) {
	if *verbose {
		log.Println("Channel type:", newChannel.ChannelType())
	}
	if t := newChannel.ChannelType(); t == "direct-tcpip" {
		handleDirect(newChannel, ports)
		return
	}

	newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Only \"direct-tcpip\" is accepted"))
	/*
		// TODO: USE THIS ONLY FOR USING SSH ESCAPE SEQUENCES
		c, _, err := newChannel.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			d := make([]byte, 4096)
			c.Read(d)
		}()
		return
	*/

}

func handleDirect(newChannel ssh.NewChannel, ports []uint32) {
	var payload directTCPPayload
	if err := ssh.Unmarshal(newChannel.ExtraData(), &payload); err != nil {
		log.Printf("Could not unmarshal extra data: %s\n", err)

		newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Bad payload"))
		return
	}

	if payload.Addr != "localhost" {
		log.Printf("Tried to connect to prohibited host: %s", payload.Addr)
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
		log.Printf("Tried to connect to prohibited port: %d", payload.Port)
		return
	}

	// At this point, we have the opportunity to reject the clients
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("Could not accept channel (%s)", err)
		return
	}
	go ssh.DiscardRequests(requests)

	addr := fmt.Sprintf("%s:%d", payload.Addr, payload.Port)
	if *verbose {
		log.Println("Dialing:", addr)
	}

	rconn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("Could not dial remote (%s)", err)
		connection.Close()
		return
	}

	serve(connection, rconn)
}

func handleTcpIpForward(conn *ssh.ServerConn, req *ssh.Request) {
	var payload tcpIpForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		log.Println("Unable to unmarshal payload")
		req.Reply(false, []byte{})
	}

	log.Println("Request:", req.Type, req.WantReply, payload)

	log.Printf("Request to listen on %s:%d", payload.Addr, payload.Port)

	if payload.Addr != "localhost" {
		log.Printf("Payload address is not \"localhost\"")
		req.Reply(false, []byte{})
		return
	}

	// TODO: Check port

	laddr := payload.Addr
	lport := payload.Port

	// TODO: We currently bind to localhost:port, and not to :port
	// Need to figure out what we want - perhaps just part of policy
	bind := fmt.Sprintf("%s:%d", laddr, lport)
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		log.Printf("Listen failed for %s", bind)
		req.Reply(false, []byte{})
		return
	}

	globalListens[bind] = ln

	// Tell client everything is OK
	reply := tcpIpForwardPayloadReply{lport}
	req.Reply(true, ssh.Marshal(&reply))

	// Ensure that we get notified when the client connection is (unexpectedly)
	// closed
	go func() {
		err := conn.Wait()
		if *verbose {
			log.Printf("SSH connection closed: %s. Stopping listen", err)
		}
		ln.Close()
		delete(globalListens, bind)

		// We don't close existing connections
	}()

	// Start listening for connections
	go func() {
		for {
			lconn, err := ln.Accept()
			if err != nil {
				log.Println("Accept failed")
				break
			}

			go func() {
				remoteaddr := lconn.RemoteAddr().String()

				p_index := strings.LastIndex(remoteaddr, ":")
				raddr := remoteaddr[:p_index]
				rport, err := strconv.ParseUint(remoteaddr[p_index+1:], 10, 32)
				if err != nil {
					log.Printf("Unable to parse RemoteAddr! (%s)", err)
					lconn.Close()
					return
				}

				payload := forwardedTCPPayload{laddr, lport, raddr, uint32(rport)}
				mpayload := ssh.Marshal(&payload)

				// Open channel with client
				c, requests, err := conn.OpenChannel("forwarded-tcpip", mpayload)
				if err != nil {
					log.Printf("Error: %s", err)
					log.Println("Unable to get channel. Hanging up requesting party!")
					lconn.Close()
					return
				}
				go ssh.DiscardRequests(requests)

				serve(c, lconn)
			}()
		}
	}()
}

func handleTcpIPForwardCancel(req *ssh.Request) {
	var payload tcpIpForwardCancelPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		log.Println("Unable to unmarshal cancel payload")
		req.Reply(false, []byte{})
	}

	bound := fmt.Sprintf("%s:%d", payload.Addr, payload.Port)

	if listener, found := globalListens[bound]; found {
		listener.Close()
		delete(globalListens, bound)
		req.Reply(true, []byte{})
	}

	req.Reply(false, []byte{})
}

func serve(cssh ssh.Channel, conn net.Conn) {
	close := func() {
		cssh.Close()
		conn.Close()
		if *verbose {
			log.Printf("Channel closed")
		}
	}

	var once sync.Once
	go func() {
		io.Copy(cssh, conn)
		once.Do(close)
	}()
	go func() {
		io.Copy(conn, cssh)
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

func loadHostKeys(config *ssh.ServerConfig) {
	privateBytes, err := ioutil.ReadFile(*hostkey)
	if err != nil {
		log.Fatal("Failed to load private key (./id_rsa)")
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)
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
			log.Fatal(fmt.Errorf("Only one option is accepted: \"ports=...\""))
		}

		option := options[0]

		if !strings.HasPrefix(option, "ports=") {
			log.Fatal(fmt.Errorf("Options does not start with \"ports=\""))
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
