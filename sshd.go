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
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	// Contains a mapping of authorised keys to permissions for said key
	authorisedKeys map[string]deviceInfo

	listenaddr     = flag.String("listenaddr", "0.0.0.0", "Addr to listen on for incoming ssh connections")
	listenport     = flag.Int("listenport", 2200, "Port to listen on for incoming ssh connections")
	hostkey        = flag.String("hostkey", "id_rsa", "Server host key to load")
	authorisedkeys = flag.String("authorisedkeys", "authorized_keys", "Authorised keys")
	verbose        = flag.Bool("verbose", false, "Enable verbose mode")
	debug          = flag.Bool("debug", false, "Enable debug mode")

	// Currently the timeouts are not separate for read and write deadlines.
	// This could be done, but I currently don't really see a reason for this.
	maintimeout      = flag.Duration("main-timeout", time.Duration(2)*time.Minute, "Client socket timeout")
	directtimeout    = flag.Duration("direct-timeout", time.Duration(2)*time.Minute, "direct-tcpip timeout")
	forwardedtimeout = flag.Duration("forwarded-timeout", time.Duration(2)*time.Minute, "forwarded-tcpip timeout")

	// Mutex protecting 'authorisedKeys' map
	authmutex sync.Mutex
)

// Structure that holds all information for each connection/client
type sshClient struct {
	Name string

	// We keep track of the normal Conn as well so that we have access to the
	// SetDeadline() methods
	Conn net.Conn

	SshConn *ssh.ServerConn

	// Listener sockets opened by the client
	Listeners map[string]net.Listener

	AllowedLocalPorts  []uint32
	AllowedRemotePorts []uint32

	// This indicates that a client is shutting down. When a client is stopping,
	// we do not allow new listening requests, to prevent a listener connection
	// being opened just after we closed all of them.
	Stopping    bool
	ListenMutex sync.Mutex
}

// Structure containing what address/port we should bind on, for forwarded-tcpip
// connections
type bindInfo struct {
	Bound string
	Port  uint32
	Addr  string
}

// Information parsed from the authorized_keys file
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

// Function that can be used to implement calls to SetDeadline() after
// read/writes in copyTimeout()
type TimeoutFunc func()

func main() {
	flag.Parse()

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			authmutex.Lock()
			defer authmutex.Unlock()
			if deviceinfo, found := authorisedKeys[string(key.Marshal())]; found {
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

		tcpConn.SetDeadline(time.Now().Add(*maintimeout))

		// We perform the ssh handshake in a goroutine so the handshake cannot
		// block incoming connections.
		go func() {
			sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, config)
			if err != nil {
				log.Printf("Failed to handshake: %s (rip: %v)", err, tcpConn.RemoteAddr())
				return
			}

			client := sshClient{sshConn.Permissions.CriticalOptions["name"], tcpConn, sshConn, make(map[string]net.Listener), nil, nil, false, sync.Mutex{}}
			allowedLocalPorts := sshConn.Permissions.CriticalOptions["localports"]
			allowedRemotePorts := sshConn.Permissions.CriticalOptions["remoteports"]

			if *verbose {
				log.Printf("[%s] Connection from %s (%s). Allowed local ports: %s remote ports: %s", client.Name, sshConn.RemoteAddr(), sshConn.ClientVersion(), allowedLocalPorts, allowedRemotePorts)
			}

			// Parsing a second time should not error, so we can ignore the error
			// safely
			client.AllowedLocalPorts, _ = parsePorts(allowedLocalPorts)
			client.AllowedRemotePorts, _ = parsePorts(allowedRemotePorts)

			go func() {
				err := client.SshConn.Wait()
				client.ListenMutex.Lock()
				client.Stopping = true

				if *verbose {
					log.Printf("[%s] SSH connection closed: %s", client.Name, err)
				}
				for bind, listener := range client.Listeners {
					if *verbose {
						log.Printf("[%s] Closing listener bound to %s", client.Name, bind)
					}
					listener.Close()
				}
				client.ListenMutex.Unlock()
			}()

			// Accept requests & channels
			go handleRequest(&client, reqs)
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
	if *debug {
		log.Printf("[%s] Channel type: %v", client.Name, newChannel.ChannelType())
	}
	if t := newChannel.ChannelType(); t == "direct-tcpip" {
		handleDirect(client, newChannel)
		return
	}

	newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Only \"direct-tcpip\" is accepted"))
	/*
		// XXX: Use this only for testing purposes -- I add this in if/when I
		// want to use the ssh escape sequences from ssh (those only work in an
		// interactive session)
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
		log.Printf("[%s] Could not unmarshal extra data: %s", client.Name, err)

		newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Bad payload"))
		return
	}

	/*
		// XXX: Is this sensible?
		if payload.Addr != "localhost" && payload.Addr != "::1" && payload.Addr != "127.0.0.1" {
			log.Printf("[%s] Tried to connect to prohibited host: %s", client.Name, payload.Addr)
			newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Bad addr"))
			return
		}
	*/

	if !portPermitted(payload.Port, client.AllowedLocalPorts) {
		newChannel.Reject(ssh.Prohibited, fmt.Sprintf("Bad port"))
		log.Printf("[%s] Tried to connect to prohibited port: %d", client.Name, payload.Port)
		return
	}

	connection, requests, err := newChannel.Accept()
	if err != nil {
		log.Printf("[%s] Could not accept channel (%s)", client.Name, err)
		return
	}
	go ssh.DiscardRequests(requests)

	addr := fmt.Sprintf("[%s]:%d", payload.Addr, payload.Port)
	if *verbose {
		log.Printf("[%s] Dialing: %s", client.Name, addr)
	}

	rconn, err := net.Dial("tcp", addr)
	if err != nil {
		log.Printf("[%s] Could not dial remote (%s)", client.Name, err)
		connection.Close()
		return
	}

	serve(connection, rconn, client, *directtimeout)
}

func handleTcpIpForward(client *sshClient, req *ssh.Request) (net.Listener, *bindInfo, error) {
	var payload tcpIpForwardPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		log.Printf("[%s] Unable to unmarshal payload", client.Name)
		req.Reply(false, []byte{})
		return nil, nil, fmt.Errorf("Unable to parse payload")
	}

	if *verbose {
		log.Printf("[%s] Request: %s %v %v", client.Name, req.Type, req.WantReply, payload)
		log.Printf("[%s] Request to listen on %s:%d", client.Name, payload.Addr, payload.Port)
	}

	if payload.Addr != "localhost" && payload.Addr != "" {
		log.Printf("[%s] Payload address is not \"localhost\" or empty: %s", client.Name, payload.Addr)
		req.Reply(false, []byte{})
		return nil, nil, fmt.Errorf("Address is not permitted")
	}

	if !portPermitted(payload.Port, client.AllowedRemotePorts) {
		log.Printf("[%s] Port is not permitted: %d", client.Name, payload.Port)
		req.Reply(false, []byte{})
		return nil, nil, fmt.Errorf("Port is not permitted")
	}

	laddr := payload.Addr
	lport := payload.Port

	bind := fmt.Sprintf("%s:%d", laddr, lport)
	ln, err := net.Listen("tcp", bind)
	if err != nil {
		log.Printf("[%s] Listen failed for %s", client.Name, bind)
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
				log.Printf("[%s] Accept failed with timeout: %s", client.Name, err)
				continue
			}
			if neterr.Temporary() {
				log.Printf("[%s] Accept failed with temporary: %s", client.Name, err)
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
	c, requests, err := client.SshConn.OpenChannel("forwarded-tcpip", mpayload)
	if err != nil {
		log.Printf("[%s] Unable to get channel: %s. Hanging up requesting party!", client.Name, err)
		lconn.Close()
		return
	}
	if *verbose {
		log.Printf("[%s] Channel opened for client", client.Name)
	}
	go ssh.DiscardRequests(requests)

	serve(c, lconn, client, *forwardedtimeout)
}

func handleTcpIPForwardCancel(client *sshClient, req *ssh.Request) {
	if *verbose {
		log.Printf("[%s] \"cancel-tcpip-forward\" called by client", client.Name)
	}
	var payload tcpIpForwardCancelPayload
	if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
		log.Printf("[%s] Unable to unmarshal cancel payload", client.Name)
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

func handleRequest(client *sshClient, reqs <-chan *ssh.Request) {
	for req := range reqs {
		client.Conn.SetDeadline(time.Now().Add(*maintimeout))

		if *debug {
			log.Printf("[%s] Out of band request: %v %v", client.Name, req.Type, req.WantReply)
		}

		// RFC4254: 7.1 for forwarding
		if req.Type == "tcpip-forward" {
			client.ListenMutex.Lock()
			/* If we are closing, do not set up a new listener */
			if client.Stopping {
				client.ListenMutex.Unlock()
				req.Reply(false, []byte{})
				continue
			}

			listener, bindinfo, err := handleTcpIpForward(client, req)
			if err != nil {
				client.ListenMutex.Unlock()
				continue
			}

			client.Listeners[bindinfo.Bound] = listener
			client.ListenMutex.Unlock()

			go handleListener(client, bindinfo, listener)
			continue
		} else if req.Type == "cancel-tcpip-forward" {
			client.ListenMutex.Lock()
			handleTcpIPForwardCancel(client, req)
			client.ListenMutex.Unlock()
			continue
		} else {
			// Discard everything else
			req.Reply(false, []byte{})
		}
	}
}

func serve(cssh ssh.Channel, conn net.Conn, client *sshClient, timeout time.Duration) {
	// TODO: Maybe just do this with defer instead? (And only one copy in a
	// goroutine)
	close := func() {
		cssh.Close()
		conn.Close()
		if *verbose {
			log.Printf("[%s] Channel closed.", client.Name)
		}
	}

	// TODO: Share timeout between both the read-conn and the write-conn
	var once sync.Once
	go func() {
		//io.Copy(cssh, conn)
		bytes_written, err := copyTimeout(cssh, conn, func() {
			if *debug {
				log.Printf("[%s] Updating deadline for direct|forwarded socket and main socket (sending data)", client.Name)
			}
			conn.SetDeadline(time.Now().Add(timeout))
			client.Conn.SetDeadline(time.Now().Add(*maintimeout))
		})
		if err != nil {
			if *debug {
				log.Printf("[%s] copyTimeout failed with: %s", client.Name, err)
			}
		}
		if *verbose {
			log.Printf("[%s] Connection closed, bytes written: %d", client.Name, bytes_written)
		}
		once.Do(close)
	}()
	go func() {
		//io.Copy(conn, cssh)
		bytes_written, err := copyTimeout(conn, cssh, func() {
			if *debug {
				log.Printf("[%s] Updating deadline for direct|forwarded socket and main socket (received data)", client.Name)
			}
			conn.SetDeadline(time.Now().Add(timeout))
			client.Conn.SetDeadline(time.Now().Add(*maintimeout))
		})
		if err != nil {
			if *debug {
				log.Printf("[%s] copyTimeout failed with: %s", client.Name, err)
			}
		}
		if *verbose {
			log.Printf("[%s] Connection closed, bytes written: %d", client.Name, bytes_written)
		}
		once.Do(close)
	}()
}

// Changed from pkg/io/io.go copyBuffer
func copyTimeout(dst io.Writer, src io.Reader, timeout TimeoutFunc) (written int64, err error) {
	buf := make([]byte, 32*1024)

	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			timeout()

			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
			timeout()
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
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
