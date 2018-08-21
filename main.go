package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/chiefy/linodego"
	"github.com/danhigham/scp"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
)

var escapePrompt = []byte("$ ")

type TokenSource struct {
	AccessToken string
}

func (t *TokenSource) Token() (*oauth2.Token, error) {
	token := &oauth2.Token{
		AccessToken: t.AccessToken,
	}
	return token, nil
}

func check(e error) {
	if e != nil {
		log.Panic(e)
	}
}

func main() {

	args := os.Args[1:]
	configFolder := args[0]

	privateKey, err := ssh.ParsePrivateKey([]byte(os.Getenv("RSA_KEY")))
	green := color.New(color.FgGreen)
	boldGreen := green.Add(color.Bold)

	messages := make(chan string)
	go func() {
		for {
			msg := <-messages
			msgs := strings.Split(msg, "\n")

			if strings.Index(msg, "\n") > -1 {
				for _, m := range msgs {
					if len(strings.TrimSpace(m)) > 0 {
						t := time.Now()
						boldGreen.Print(fmt.Sprintf("%s - ", t.Format("2006-01-02 15:04:05")))
						fmt.Printf("%s\n", m)
					}
				}
			} else {
				fmt.Print(msg)
			}
		}
	}()

	apiToken, _ := os.LookupEnv("LINODE_TOKEN")

	linodeClient := linodego.NewClient(&apiToken, nil)

	messages <- "Creating Linode instance\n"

	//name := "get-iplayer"
	//sshKeyID, err := strconv.Atoi(os.Getenv("SSH_KEY_ID"))

	linode, err := linodeClient.CreateInstance(&linodego.InstanceCreateOptions{
		//Label:          name,
		Region:         "eu-west",
		Type:           "g6-standard-2",
		Image:          "linode/containerlinux",
		RootPass:       "password123",
		AuthorizedKeys: []string{os.Getenv("RSA_KEY_PUB")},
	})

	check(err)

	//ctx := context.TODO()

	event, err := linodeClient.WaitForEventFinished(linode.ID, linodego.EntityLinode, linodego.ActionLinodeCreate, *linode.Created, 240)
	check(err)
	if err := linodeClient.MarkEventRead(event); err != nil {
		check(err)
	}

	// wait for the IP address

	ipAddress := linode.IPv4[0]

	check(err)

	/* messages <- "Waiting for IP Address\n"

	for ipAddress == "" {
		time.Sleep(2 * time.Second)
		dl, _, err := client.Droplets.Get(ctx, newDroplet.ID)
		ipAddress, err = dl.PublicIPv4()

		if err != nil {
			log.Panic("Unable to get IP address: %s\n\n", err)
		}
	} */

	sshAddress := fmt.Sprintf("%s:22", ipAddress)

	// wait for SSH
	messages <- "Waiting for SSH\n"
	_, connErr := net.DialTimeout("tcp", sshAddress, 2*time.Second)

	for connErr != nil {
		_, connErr = net.DialTimeout("tcp", sshAddress, 2*time.Second)
	}

	messages <- fmt.Sprintf("Connecting to %s\n", ipAddress)

	// try and connect
	config := &ssh.ClientConfig{
		User: "core",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(privateKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	sshClient, err := ssh.Dial("tcp", sshAddress, config)
	check(err)

	session, err := sshClient.NewSession()
	check(err)

	var b bytes.Buffer  // import "bytes"
	session.Stdout = &b // get output

	defer session.Close()

	messages <- "Starting docker container\n"

	cmds := []string{
		"docker run -d --name get-iplayer harbor.high.am:443/get-iplayer/get-iplayer tail -f /root/get_iplayer/README.md",
		"docker exec -it get-iplayer curl ifconfig.co/json | jq",
		"docker exec -it get-iplayer git clone https://github.com/danhigham/get_iplayer_config.git /root/.get_iplayer",
		"docker exec -it get-iplayer mkdir -p /tmp/iplayer_incoming",
		"docker exec -it get-iplayer /root/get_iplayer/get_iplayer --refresh",
		"docker exec -it get-iplayer /root/get_iplayer/get_iplayer --pvr -v",
		"docker cp get-iplayer:/root/.get_iplayer /home/core",
		"docker cp get-iplayer:/tmp/iplayer_incoming /home/core",
		"tar cvzf iplayer_config.tgz -C /home/core/.get_iplayer .",
		"tar cvzf iplayer_incoming.tgz -C /home/core/iplayer_incoming .",
	}

	err = executeCmds(cmds, sshClient, messages)
	check(err)

	messages <- "Downloading files from droplet\n"

	err = downloadRemoteFiles([]string{"/home/core/iplayer_config.tgz", "/home/core/iplayer_incoming.tgz"}, sshClient, messages)
	check(err)

	messages <- "Deleting droplet\n"
	linodeClient.DeleteInstance(linode.ID)

	messages <- "Finishing up\n"
	cmd := exec.Command("./scheduler/ci/commit-changes", configFolder)
	out, err := cmd.Output()

	check(err)
	messages <- string(out)

}

func downloadRemoteFiles(files []string, client *ssh.Client, messages chan string) error {
	for _, file := range files {
		messages <- fmt.Sprintf("Downloading %s\n", file)
		fileSize, err := getRemoteFileSize(file, client)
		if err != nil {
			return err
		}
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		err = scp.GetPath(fileSize, file, path.Base(file), session)
		if err != nil {
			return err
		}
	}

	return nil
}

func getRemoteFileSize(filename string, client *ssh.Client) (int, error) {
	result, err := evalCmd(fmt.Sprintf("wc -c %s", filename), client)
	if err != nil {
		return -1, err
	}
	fileSize := strings.Split(strings.TrimSpace(string(result)), " ")[0]
	return strconv.Atoi(fileSize)
}

func evalCmd(cmd string, client *ssh.Client) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	return session.Output(cmd)
}

func executeCmds(cmd []string, client *ssh.Client, messages chan string) error {

	session, err := client.NewSession()

	if err != nil {
		return err
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("vt220", 80, 40, modes); err != nil {
		return err
	}

	w, err := session.StdinPipe()
	if err != nil {
		return err
	}
	r, err := session.StdoutPipe()
	if err != nil {
		return err
	}

	if err := session.Start("/usr/bin/bash"); err != nil {
		return err
	}

	readUntil(r, escapePrompt, messages)

	for _, currentCmd := range cmd {
		messages <- fmt.Sprintf("Running command '%s'\n", currentCmd)
		write(w, currentCmd)

		_, err := readUntil(r, escapePrompt, messages)
		if err != nil {
			return err
		}
	}

	write(w, "exit")
	session.Wait()

	return nil
}

func write(w io.WriteCloser, command string) error {
	_, err := w.Write([]byte(command + "\n"))
	return err
}

func readUntil(r io.Reader, matchingByte []byte, messages chan string) (*string, error) {
	var buf [10240 * 1024]byte
	var t int
	o := 0
	for {

		n, err := r.Read(buf[t:])
		if err != nil {
			return nil, err
		}
		t += n
		messages <- string(buf[o:t])
		o = t
		if isMatch(buf[:t], t, matchingByte) {
			stringResult := string(buf[:t])
			return &stringResult, nil
		}
	}
}

func isMatch(bytes []byte, t int, matchingBytes []byte) bool {
	if t >= len(matchingBytes) {
		for i := 0; i < len(matchingBytes); i++ {
			if bytes[t-len(matchingBytes)+i] != matchingBytes[i] {
				return false
			}
		}
		return true
	}
	return false
}
