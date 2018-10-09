package main

import (
	"bytes"
	"context"
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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"

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

	messages <- "Creating EC2 instance\n"

	// AWS_ACCESS_KEY_ID
	// AWS_SECRET_ACCESS_KEY

	svc := ec2.New(session.New(&aws.Config{Region: aws.String("eu-west-2")}))
	reservation, err := svc.RunInstances(&ec2.RunInstancesInput{
		// An Amazon Linux AMI ID for t2.micro instances in the us-west-2 region
		ImageId:        aws.String("ami-00985bd8806d05c41"),
		InstanceType:   aws.String("t3.medium"),
		KeyName:        aws.String("get-iplayer"),
		SecurityGroups: []*string{aws.String("allow-ssh")},
		MinCount:       aws.Int64(1),
		MaxCount:       aws.Int64(1),
		BlockDeviceMappings: []*ec2.BlockDeviceMapping{
			{
				DeviceName: aws.String("/dev/xvda"),
				Ebs: &ec2.EbsBlockDevice{
					VolumeSize: aws.Int64(200),
				},
			},
		},
	})

	check(err)

	instanceIds := make([]*string, len(reservation.Instances))

	for k, v := range reservation.Instances {
		instanceIds[k] = v.InstanceId
	}

	statusInput := ec2.DescribeInstancesInput{
		InstanceIds: instanceIds,
	}

	messages <- "Waiting for instance to become running\n"

	ctx := context.Background()

	instanceOkErr := svc.WaitUntilInstanceRunningWithContext(ctx, &statusInput)
	check(instanceOkErr)

	description, descriptionErr := svc.DescribeInstancesWithContext(ctx, &statusInput)
	check(descriptionErr)

	instance := description.Reservations[0].Instances[0]

	ipAddress := instance.PublicIpAddress
	instanceId := instance.InstanceId
	check(err)

	sshAddress := fmt.Sprintf("%s:22", *ipAddress)
	messages <- fmt.Sprintf("SSH address is %s\n", sshAddress)

	// wait for SSH
	messages <- "Waiting for SSH\n"
	_, connErr := net.DialTimeout("tcp", sshAddress, 2*time.Second)

	for connErr != nil {
		_, connErr = net.DialTimeout("tcp", sshAddress, 2*time.Second)
	}

	messages <- fmt.Sprintf("Connecting to %s\n", sshAddress)

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
		"docker exec -it get-iplayer git clone https://git.high.am/danhigham/get-iplayer-config.git /root/.get_iplayer",
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

	messages <- "Downloading files from EC2 instance\n"

	err = downloadRemoteFiles([]string{"/home/core/iplayer_config.tgz", "/home/core/iplayer_incoming.tgz"}, sshClient, messages)
	check(err)

	messages <- "Deleting EC2 instance\n"
	_, err = svc.TerminateInstances(&ec2.TerminateInstancesInput{
		InstanceIds: []*string{instanceId},
	})

	check(err)

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
