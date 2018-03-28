package main

import (
	"bytes"
	"fmt"
	"github.com/digitalocean/godo"
	"github.com/digitalocean/godo/context"
	"golang.org/x/crypto/ssh"
	"golang.org/x/oauth2"
	"github.com/danhigham/scp"
	"log"
	"github.com/fatih/color"
	"strings"
	"net"
	"os"
	"time"
	"strconv"
	"path"
	"os/exec"
	"io"
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
	check(err)

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

	tokenSource := &TokenSource{
		AccessToken: os.Getenv("DO_TOKEN"),
	}

	oauthClient := oauth2.NewClient(context.Background(), tokenSource)
	client := godo.NewClient(oauthClient)

	messages <- "Creating CoreOS droplet\n"

	dropletName := "get-iplayer"
	sshKeyID, err := strconv.Atoi(os.Getenv("SSH_KEY_ID"))

	check(err)

	createRequest := &godo.DropletCreateRequest{
		Name:   dropletName,
		Region: "lon1",
		Size:   "512mb",
		Image: godo.DropletCreateImage{
			Slug: "coreos-stable",
		},
		SSHKeys: []godo.DropletCreateSSHKey{godo.DropletCreateSSHKey{
			ID: sshKeyID,
		}},
	}

	ctx := context.TODO()

	newDroplet, _, err := client.Droplets.Create(ctx, createRequest)

	check(err)

	// wait for the IP address

	ipAddress, err := newDroplet.PublicIPv4()

	check(err)

	messages <- "Waiting for IP Address\n"

	for ipAddress == "" {
		time.Sleep(2 * time.Second)
		dl, _, err := client.Droplets.Get(ctx, newDroplet.ID)
		ipAddress, err = dl.PublicIPv4()

		if err != nil {
			log.Panic("Unable to get IP address: %s\n\n", err)
		}
	}

	sshAddress := fmt.Sprintf("%s:22", ipAddress)

	// wait for SSH
	messages <- "Waiting for SSH\n"
	_, connErr := net.DialTimeout("tcp", sshAddress, 2*time.Second)

	for connErr != nil {
		_, connErr = net.DialTimeout("tcp", sshAddress, 2*time.Second)
	}

	messages <- "Connecting\n"

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

	//messages <- "Creating config archive\n"

	//cmd := exec.Command("tar", "cvzf", "config.tgz", "-C", configFolder, ".")
	//out, err := cmd.Output()

	//check(err)

	//messages <- string(out)

	// Copy config files
	//err = scp.CopyPath("config.tgz", "/home/core/iplayer_config.tgz", session)
	//check(err)

	messages <- "Starting docker container\n"

	cmds := []string {
		"docker run -d --name get-iplayer danhigham/get-iplayer tail -f /root/get_iplayer/README.md",
		//"mkdir -pv /home/core/.get_iplayer",
		//"tar xvzf /home/core/iplayer_config.tgz -C /home/core/.get_iplayer",
		//"docker cp /home/core/.get_iplayer get-iplayer:/root/.get_iplayer",
		"docker exec -it get-iplayer git clone https://github.com/danhigham/get_iplayer_config.git /root/.get_iplayer",
		"docker exec -it get-iplayer /root/get_iplayer/get_iplayer --pvr",
		"docker cp get-iplayer:/root/.get_iplayer /home/core",
		"docker cp get-iplayer:/tmp/iplayer_incoming /home/core",
		"tar cvzf iplayer_config.tgz -C /home/core/.get_iplayer .",
		"tar cvzf iplayer_incoming.tgz -C /home/core/iplayer_incoming .",
		//"pushd /home/core/.get_iplayer; tar cvzf /home/core/iplayer_config.tgz .; popd;",
		//"pushd /home/core/iplayer_incoming; tar cvzf /home/core/iplayer_incoming.tgz *; popd;", 
	}

	err = executeCmds(cmds, sshClient, messages)
	check(err)

	messages <- "Downloading files from droplet\n"  

	err = downloadRemoteFiles([]string {"/home/core/iplayer_config.tgz", "/home/core/iplayer_incoming.tgz"}, sshClient, messages)
	check(err)

	messages <- "Deleting droplet\n"
	client.Droplets.Delete(ctx, newDroplet.ID)
		
	messages <- "Expanding archives\n"	
	cmd := exec.Command("tar", "xvzf", "./iplayer_config.tgz", "-C", fmt.Sprintf("%s-out", configFolder))
	out, err := cmd.Output()

	check(err)
	messages <- string(out)
	
	cmd = exec.Command("tar", "xvzf", "./iplayer_incoming.tgz")
	out, err = cmd.Output()

	check(err)
	messages <- string(out)
}

func downloadRemoteFiles(files []string, client *ssh.Client, messages chan string) error {
	for _, file := range files {
		messages <- fmt.Sprintf("Downloading %s\n", file)
		fileSize, err := getRemoteFileSize(file, client)
		if (err != nil) {
			return err
		}
		session, err := client.NewSession()
		if err != nil {
			return err
		}
		err = scp.GetPath(fileSize, file, path.Base(file), session)
		if (err != nil) {
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

func executeCmds(cmd []string, client *ssh.Client, messages chan string) (error) {
	
	
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
    var buf [1024 * 1024]byte
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
            if bytes[t - len(matchingBytes) + i] != matchingBytes[i] {
                return false
            }
        }
        return true
    }
    return false
}
