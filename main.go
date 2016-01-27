package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const appname = "multisshtail"

var currentUser = func() string {
	u, err := user.Current()
	if err != nil {
		panic(err)
	}
	return u.Name
}()

func main() {
	log.SetFlags(0)
	log.SetPrefix(appname + ": ")

	userFlag := flag.String("user", currentUser, "user to use on the remote machine")
	addrsFlag := flag.String("addrs", "", "comma separated list of address to ssh into")
	filesFlag := flag.String("files", "", "comma separated list of path where files to tail are found")
	sudoFlag := flag.Bool("sudo", false, "whether to run the tail as sudo")
	flag.Parse()

	if len(*addrsFlag) == 0 {
		log.Fatal("provide at least 1 address")
	}
	if len(*filesFlag) == 0 {
		log.Fatal("provide at least 1 file")
	}

	addrs := strings.Split(*addrsFlag, ",")
	files := strings.Split(*filesFlag, ",")

	auth, done, err := sshAgent()
	if err != nil {
		log.Fatalf("no ssh agent: %v", err)
	}
	defer done()

	clients, doneClient, err := connectHost(addrs, &ssh.ClientConfig{
		User: *userFlag,
		Auth: []ssh.AuthMethod{auth},
	})
	if err != nil {
		log.Fatalf("connecting to addresses: %v", err)
	}
	defer doneClient()

	linec, errc := tailFilesOnClients(clients, files, *sudoFlag)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for err := range errc {
			log.Printf("error: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		for line := range linec {
			fmt.Println(line)
		}
	}()
	wg.Wait()
}

func tailFilesOnClients(clients []*ssh.Client, files []string, sudo bool) (<-chan string, <-chan error) {
	linec := make(chan string, len(clients)*len(files))
	errc := make(chan error, len(clients)*len(files))

	go func() {
		defer close(linec)
		defer close(errc)
		var wg sync.WaitGroup
		for _, client := range clients {
			wg.Add(1)
			go func(client *ssh.Client) {
				defer wg.Done()
				tailFilesOnClient(client, files, sudo, linec, errc)
			}(client)
		}
		wg.Wait()
	}()

	return linec, errc
}

func tailFilesOnClient(client *ssh.Client, files []string, sudo bool, linec chan<- string, errc chan<- error) {
	var sessions []*ssh.Session
	closeSessions := func() {
		for _, session := range sessions {
			_ = session.Signal(ssh.SIGKILL)
			_ = session.Close()
		}
	}

	var wg sync.WaitGroup
	for _, file := range files {
		session, err := client.NewSession()
		if err != nil {
			closeSessions()
			errc <- fmt.Errorf("can't open session: %v", err)
			return
		}
		sessions = append(sessions, session)

		wg.Add(1)
		go func(file string) {
			defer wg.Done()
			err := tailFile(session, file, sudo, linec)
			if err != nil {
				errc <- err
			}
		}(file)

	}

	wg.Wait()
}

func tailFile(session *ssh.Session, file string, sudo bool, linec chan<- string) error {

	var command string
	if sudo {
		command = fmt.Sprintf("sudo /usr/bin/env tail -F %s", file)
	} else {
		command = fmt.Sprintf("/usr/bin/env tail -F %s", file)
	}

	var wg sync.WaitGroup
	errc := make(chan error, 3)
	consumeStream := func(r io.Reader) {
		defer wg.Done()
		scan := bufio.NewScanner(r)
		scan.Split(bufio.ScanLines)
		for scan.Scan() {
			linec <- scan.Text()
		}
		if err := scan.Err(); err != nil {
			errc <- err
		}
	}

	stderr, err := session.StderrPipe()
	if err != nil {
		return fmt.Errorf("opening stderr: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("opening stdout: %v", err)
	}

	wg.Add(1)
	go consumeStream(stderr)
	go consumeStream(stdout)

	if err := session.Start(command); err != nil {
		return err
	}
	wg.Add(1)
	go func() {
		if err := session.Wait(); err != nil {
			errc <- err
		}
	}()

	go func() {
		wg.Wait()
		close(errc)
	}()

	return <-errc
}

func sshAgent() (ssh.AuthMethod, func(), error) {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, func() {}, err
	}
	method := ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers)
	return method, func() { _ = sshAgent.Close() }, nil
}

func connectHost(addrs []string, opts *ssh.ClientConfig) ([]*ssh.Client, func(), error) {
	var wg sync.WaitGroup
	clientc := make(chan *ssh.Client, len(addrs))
	errc := make(chan error, len(addrs))
	for _, addr := range addrs {
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()

			client, err := ssh.Dial("tcp", addr, opts)
			if err != nil {
				errc <- fmt.Errorf("can't ssh into address %q, %v", addr, err)
			} else {
				clientc <- client
			}
		}(addr)
	}
	go func() {
		wg.Wait()
		close(clientc)
	}()

	var clients []*ssh.Client
	for client := range clientc {
		clients = append(clients, client)
	}
	closeClients := func() {
		for _, client := range clients {
			client.Close()
		}
	}

	close(errc)
	var errs []string
	for err := range errc {
		errs = append(errs, err.Error())
	}

	if len(errs) != 0 {
		closeClients()
		return nil, nil, fmt.Errorf("failed to connect: %v", strings.Join(errs, ", "))
	}
	return clients, closeClients, nil
}
