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

// TODO: Use defer where useful

var (
	authorisedKeys map[string]string

	listenport     = flag.Int("listenport", 2200, "Port to listen on for incoming ssh connections")
	hostkey        = flag.String("hostkey", "id_rsa", "Server host key to load")
	authorisedkeys = flag.String("authorisedkeys", "authorized_keys", "Authorised keys")
	verbose        = flag.Bool("verbose", false, "Enable verbose mode")
)

type sshClient struct {
	Name               string
	Conn               *ssh.ServerConn
	Listeners          map[string]net.Listener
	AllowedLocalPorts  []uint32
	AllowedRemotePorts []uint32
}

type bindInfo struct {
	Bound string
	Port  uint32
	Addr  string
}

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

		go func() {
			// TODO: Run this in goroutine and have the rest block on it
			sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
			if err != nil {
				log.Printf("Failed to handshake (%s)", err)
				return
			}

			client := sshClient{"TODO FIXME XXX", sshConn, make(map[string]net.Listener), nil, nil}

			go func() {
				err := client.Conn.Wait()
				if *verbose {
					log.Printf("SSH connection closed for client %s: %s", client.Name, err)
				}
				// TODO: Make this safe? Is it impossible for cancel code to be
				// running at this point?
				for bind, listener := range client.Listeners {
					if *verbose {
						log.Printf("Closing listener bound to %s", bind)
					}
					listener.Close()
				}
			}()

			allowedPorts := sshConn.Permissions.CriticalOptions["ports"]

			if *verbose {
				log.Printf("Connection from %s (%s). Allowed ports: %s", sshConn.RemoteAddr(), sshConn.ClientVersion(), allowedPorts)
			}

			// Parsing a second time should not error, so we can ignore the error
			// safely
			ports, _ := parsePorts(allowedPorts)
			// TODO: Don't share same port/host limit
			client.AllowedLocalPorts = ports
			client.AllowedRemotePorts = ports

			go handleRequest(&client, reqs)

			// Accept all channels (TODO: Pass client)
			go handleChannels(&client, chans)
		}()
	}
}

func handleChannels(client *sshClient, chans <-chan ssh.NewChannel) {
	for c := range chans {
		go handleChannel(client, c)
	}
}

func handleChannel(client *sshClient, newChannel ssh.NewChannel) {
	if *verbose {
		log.Println("Channel type:", newChannel.ChannelType())
	}
	if t := newChannel.ChannelType(); t == "direct-tcpip" {
		handleDirect(client, newChannel)
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
	*/
	return

}

func handleDirect(client *sshClient, newChannel ssh.NewChannel) {
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
	for _, port := range client.AllowedLocalPorts {
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

	// At this point, we have the opportunity to reject the client's
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

func handleTcpIpForward(client *sshClient, req *ssh.Request) (net.Listener, *bindInfo, error) {
	var payload tcpIpForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		log.Println("Unable to unmarshal payload")
		req.Reply(false, []byte{})
		return nil, nil, fmt.Errorf("Unable to parse payload")
	}

	log.Println("Request:", req.Type, req.WantReply, payload)

	log.Printf("Request to listen on %s:%d", payload.Addr, payload.Port)

	if payload.Addr != "localhost" {
		log.Printf("Payload address is not \"localhost\"")
		req.Reply(false, []byte{})
		return nil, nil, fmt.Errorf("Address is not permitted")
	}

	ok := false
	for _, port := range client.AllowedRemotePorts {
		if payload.Port == port {
			ok = true
			break
		}
	}

	if !ok {
		log.Printf("Port is not permitted.")
		req.Reply(false, []byte{})
		return nil, nil, fmt.Errorf("Port is not permitted")
	}

	laddr := payload.Addr
	lport := payload.Port

	// TODO: We currently bind to localhost:port, and not to :port
	// Need to figure out what we want - perhaps just part of policy
	//bind := fmt.Sprintf(":%d", lport)
	bind := fmt.Sprintf("%s:%d", laddr, lport)
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		log.Printf("Listen failed for %s", bind)
		req.Reply(false, []byte{})
		return nil, nil, err
	}

	// Tell client everything is OK
	reply := tcpIpForwardPayloadReply{lport}
	req.Reply(true, ssh.Marshal(&reply))

	return ln, &bindInfo{bind, lport, laddr}, nil

}

func handleListener(client *sshClient, bindinfo *bindInfo, listener net.Listener) {
	// Start listening for connections
	for {
		lconn, err := listener.Accept()
		if err != nil {
			neterr := err.(net.Error)
			if neterr.Timeout() {
				log.Println("Accept failed with timeout:", err)
				continue
			}
			if neterr.Temporary() {
				log.Println("Accept failed with temporary:", err)
				continue
			}

			break
		}

		go handleForwardTcpIp(client, bindinfo, lconn)
	}
}

func handleForwardTcpIp(client *sshClient, bindinfo *bindInfo, lconn net.Conn) {
	remotetcpaddr := lconn.RemoteAddr().(*net.TCPAddr)
	raddr := remotetcpaddr.IP.String()
	rport := uint32(remotetcpaddr.Port)

	payload := forwardedTCPPayload{bindinfo.Addr, bindinfo.Port, raddr, uint32(rport)}
	mpayload := ssh.Marshal(&payload)

	// Open channel with client
	c, requests, err := client.Conn.OpenChannel("forwarded-tcpip", mpayload)
	if err != nil {
		log.Printf("Error: %s", err)
		log.Println("Unable to get channel. Hanging up requesting party!")
		lconn.Close()
		return
	}
	go ssh.DiscardRequests(requests)

	serve(c, lconn)
}

func handleTcpIPForwardCancel(client *sshClient, req *ssh.Request) {
	if *verbose {
		log.Println("Cancel called by client", client)
	}
	var payload tcpIpForwardCancelPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		log.Println("Unable to unmarshal cancel payload")
		req.Reply(false, []byte{})
	}

	bound := fmt.Sprintf("%s:%d", payload.Addr, payload.Port)

	if listener, found := client.Listeners[bound]; found {
		listener.Close()
		delete(client.Listeners, bound)
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

func handleRequest(client *sshClient, reqs <-chan *ssh.Request) {
	for req := range reqs {
		if *verbose {
			log.Println("Out of band request:", req.Type, req.WantReply)
		}

		// RFC4254: 7.1 for forwarding
		if req.Type == "tcpip-forward" {
			listener, bindinfo, err := handleTcpIpForward(client, req)
			if err != nil {
				continue
			}

			client.Listeners[bindinfo.Bound] = listener
			go handleListener(client, bindinfo, listener)
			continue
		} else if req.Type == "cancel-tcpip-forward" {
			handleTcpIPForwardCancel(client, req)
			continue
		} else {
			// Discard everything else
			req.Reply(false, []byte{})
		}
	}
}
