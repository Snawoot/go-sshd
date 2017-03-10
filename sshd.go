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
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
)

// TODO: Use defer where useful

var (
	authorisedKeys map[string]deviceInfo

	listenaddr     = flag.String("listenaddr", "0.0.0.0", "Addr to listen on for incoming ssh connections")
	listenport     = flag.Int("listenport", 2200, "Port to listen on for incoming ssh connections")
	hostkey        = flag.String("hostkey", "id_rsa", "Server host key to load")
	authorisedkeys = flag.String("authorisedkeys", "authorized_keys", "Authorised keys")
	verbose        = flag.Bool("verbose", false, "Enable verbose mode")

	authmutex sync.Mutex
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

type deviceInfo struct {
	LocalPorts  string
	RemotePorts string
	Comment     string
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
			if deviceinfo, found := authorisedKeys[string(key.Marshal())]; found {
				authmutex.Lock()
				defer authmutex.Unlock()
				return &ssh.Permissions{
					CriticalOptions: map[string]string{"name": deviceinfo.Comment,
						"localports":  deviceinfo.LocalPorts,
						"remoteports": deviceinfo.RemotePorts},
				}, nil
			}

			return nil, fmt.Errorf("Unknown public key\n")
		},
	}

	loadHostKeys(config)
	loadAuthorisedKeys(*authorisedkeys)

	registerReloadSignal()

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *listenaddr, *listenport))
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
			sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
			if err != nil {
				log.Printf("Failed to handshake (%s)", err)
				return
			}

			client := sshClient{sshConn.Permissions.CriticalOptions["name"], sshConn, make(map[string]net.Listener), nil, nil}
			allowedLocalPorts := sshConn.Permissions.CriticalOptions["localports"]
			allowedRemotePorts := sshConn.Permissions.CriticalOptions["remoteports"]

			if *verbose {
				log.Printf("Connection from %s, %s (%s). Allowed local ports: %s remote ports: %s", client.Name, sshConn.RemoteAddr(), sshConn.ClientVersion(), allowedLocalPorts, allowedRemotePorts)
			}

			// Parsing a second time should not error, so we can ignore the error
			// safely
			client.AllowedLocalPorts, _ = parsePorts(allowedLocalPorts)
			client.AllowedRemotePorts, _ = parsePorts(allowedRemotePorts)

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

			go handleRequest(&client, reqs)
			// Accept all channels
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

	if !portPermitted(payload.Port, client.AllowedLocalPorts) {
		newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Bad port"))
		log.Printf("Tried to connect to prohibited port: %d", payload.Port)
		return
	}

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

	serve(connection, rconn, client)
}

func handleTcpIpForward(client *sshClient, req *ssh.Request) (net.Listener, *bindInfo, error) {
	var payload tcpIpForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		log.Println("Unable to unmarshal payload")
		req.Reply(false, []byte{})
		return nil, nil, fmt.Errorf("Unable to parse payload")
	}

	if *verbose {
		log.Println("Request:", req.Type, req.WantReply, payload)
		log.Printf("Request to listen on %s:%d", payload.Addr, payload.Port)
	}

	if payload.Addr != "localhost" && payload.Addr != "" {
		log.Printf("Payload address is not \"localhost\" or empty")
		req.Reply(false, []byte{})
		return nil, nil, fmt.Errorf("Address is not permitted")
	}

	if !portPermitted(payload.Port, client.AllowedRemotePorts) {
		log.Printf("Port is not permitted.")
		req.Reply(false, []byte{})
		return nil, nil, fmt.Errorf("Port is not permitted")
	}

	laddr := payload.Addr
	lport := payload.Port

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
	if *verbose {
		log.Printf("Channel opened for client %s", client.Name)
	}
	go ssh.DiscardRequests(requests)

	serve(c, lconn, client)
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

func serve(cssh ssh.Channel, conn net.Conn, client *sshClient) {
	// TODO: Maybe just do this with defer instead? (And only one copy in a
	// goroutine)
	close := func() {
		cssh.Close()
		conn.Close()
		if *verbose {
			log.Printf("Channel closed for client: %s", client.Name)
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

func loadHostKeys(config *ssh.ServerConfig) {
	privateBytes, err := ioutil.ReadFile(*hostkey)
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to load private key (%s)", *hostkey))
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)
}

func loadAuthorisedKeys(authorisedkeys string) {
	authKeys := map[string]deviceInfo{}
	authKeysBytes, err := ioutil.ReadFile(authorisedkeys)
	if err != nil {
		log.Fatal("Cannot load authorised keys")
	}

	for len(authKeysBytes) > 0 {
		pubkey, comment, options, rest, err := ssh.ParseAuthorizedKey(authKeysBytes)

		if err != nil {
			log.Printf("Error parsing line: %s", err)
			authKeysBytes = rest
			continue
		}

		devinfo := deviceInfo{Comment: comment}

		// TODO: Compatibility with permitopen=foo,permitopen=bar,
		// permitremoteopen=quux,permitremoteopen=wobble
		for _, option := range options {
			ports, err := parseOption(option, "localports")
			if err == nil {
				devinfo.LocalPorts = ports
				continue
			}
			ports, err = parseOption(option, "remoteports")
			if err == nil {
				devinfo.RemotePorts = ports
				continue
			}
			if *verbose {
				log.Println("Unknown option:", option)
			}
		}

		authKeys[string(pubkey.Marshal())] = devinfo

		authKeysBytes = rest
	}

	authmutex.Lock()
	defer authmutex.Unlock()
	authorisedKeys = authKeys
}

func registerReloadSignal() {
	c := make(chan os.Signal)
	signal.Notify(c, syscall.SIGUSR1)

	go func() {
		for sig := range c {
			_ = sig
			log.Printf("Received signal: \"%s\". Reloading authorised keys.", sig.String())
			loadAuthorisedKeys(*authorisedkeys)
		}

	}()
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

func portPermitted(port uint32, ports []uint32) bool {
	ok := false
	for _, p := range ports {
		if port == p {
			ok = true
			break
		}
	}

	return ok
}

func parseOption(option string, prefix string) (string, error) {
	str := fmt.Sprintf("%s=", prefix)
	if !strings.HasPrefix(option, str) {
		return "", fmt.Errorf("Option does not start with %s", str)
	}
	ports := option[len(str):]

	if _, err := parsePorts(ports); err != nil {
		log.Fatal(err)
	}

	return ports, nil
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
