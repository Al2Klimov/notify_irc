// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const ircUrlStructure = "irc[s]://USER[:PASS]@HOST[:PORT]/direct|channel/RECIPIENT[?insecure=1]"

var ircUrlPathStructure = regexp.MustCompile(`\A/(direct|channel)/([^/]+)\z`)

func main() {
	os.Exit(run())
}

func run() int {
	icingaTimet := flag.Int64("icinga.timet", 0, "$icinga.timet$")

	hName := flag.String("host.name", "", "$host.name$")
	hDisplayName := flag.String("host.display_name", "", "$host.display_name$")
	hActionUrl := flag.String("host.action_url", "", "$host.action_url$")
	hState := flag.String("host.state", "", "$host.state$")
	hOutput := flag.String("host.output", "", "$host.output$")

	sName := flag.String("service.name", "", "$service.name$")
	sDisplayName := flag.String("service.display_name", "", "$service.display_name$")
	sActionUrl := flag.String("service.action_url", "", "$service.action_url$")
	sState := flag.String("service.state", "", "$service.state$")
	sOutput := flag.String("service.output", "", "$service.output$")

	flag.Parse()

	if *icingaTimet == 0 {
		*icingaTimet = time.Now().Unix()
	}

	rawIrcUrl := os.Getenv("IRC_URL")
	if empty(rawIrcUrl) {
		complain("$IRC_URL missing (" + ircUrlStructure + ")")
	}

	reportService := true
	state := *sState
	output := *sOutput

	if !empty(*sName) || !empty(*sDisplayName) || !empty(*sActionUrl) || !empty(*sState) || !empty(*sOutput) {
		if empty(*hName) || empty(*sName) || empty(*sState) {
			complain("-service.* is given, missing some of: -host.name, -service.name, -service.state")
		}

		if empty(*sDisplayName) {
			sDisplayName = sName
		}
	} else if !empty(*hName) || !empty(*hDisplayName) || !empty(*hActionUrl) || !empty(*hState) || !empty(*hOutput) {
		if empty(*hName) || empty(*hState) {
			complain("-host.* is given, missing some of: -host.name, -host.state")
		}

		reportService = false
		state = *hState
		output = *hOutput
	} else {
		complain("Missing either -host.name and -host.state or -host.name, -service.name and -service.state")
	}

	if empty(*hDisplayName) {
		hDisplayName = hName
	}

	ircUrl, errUP := url.Parse(rawIrcUrl)
	if errUP != nil {
		complain("Bad IRC URL (" + ircUrlStructure + "): " + errUP.Error())
	}

	ircUrlQuery, errPQ := url.ParseQuery(ircUrl.RawQuery)
	if errPQ != nil {
		complain("Bad IRC URL (" + ircUrlStructure + "): " + errPQ.Error())
	}

	var ssl bool
	var defaultPort string

	switch ircUrl.Scheme {
	case "irc":
		ssl = false
		defaultPort = "6667"
	case "ircs":
		ssl = true
		defaultPort = "6697"
	default:
		complain("Bad protocol in IRC URL (" + ircUrlStructure + ")")
	}

	user := ircUrl.User.Username()
	if empty(user) {
		complain("Missing user in IRC URL (" + ircUrlStructure + ")")
	}

	if empty(ircUrl.Host) {
		complain("Missing host in IRC URL (" + ircUrlStructure + ")")
	}

	match := ircUrlPathStructure.FindStringSubmatch(ircUrl.Path)
	if match == nil {
		complain("Bad path in IRC URL (" + ircUrlStructure + ")")
	}

	exitSuccess := 0

	hostname, errHn := os.Hostname()
	if errHn != nil {
		_, _ = fmt.Fprintln(os.Stderr, errHn.Error())
		exitSuccess = 1

		hostname = "(unknown)"
	}

	pMark := "!"
	switch state {
	case "UP", "OK":
		pMark = "."
	}

	msg := &bytes.Buffer{}

	if reportService {
		mustFprintf(msg, "***** Service monitoring on %s *****", hostname)
		mustFprintf(msg, "\n\n%s on %s is %s%s", *sDisplayName, *hDisplayName, state, pMark)

		mustFprintf(
			msg, "\n\nWhen: %s\nHost: %s %s\nService: %s %s",
			time.Unix(*icingaTimet, 0), *hName, *hActionUrl, *sName, *sActionUrl,
		)
	} else {
		mustFprintf(msg, "***** Host monitoring on %s *****", hostname)
		mustFprintf(msg, "\n\n%s is %s%s", *hDisplayName, state, pMark)
		mustFprintf(msg, "\n\nWhen: %s\nHost: %s %s", time.Unix(*icingaTimet, 0), *hName, *hActionUrl)
	}

	mustFprintf(msg, "\nInfo:\n\n%s", output)

	buf := &bytes.Buffer{}

	if pass, _ := ircUrl.User.Password(); pass != "" {
		mustFprintf(buf, "PASS %s\r\n", pass)
	}

	mustFprintf(buf, "NICK %s\r\n", user)
	mustFprintf(buf, "USER %s 0.0.0.0 0.0.0.0 %s\r\n", user, user)

	recipient := match[2]
	if match[1] == "channel" {
		recipient = "#" + recipient
	}

	emptyLine := []byte{'.'}

	for _, line := range bytes.Split(bytes.ReplaceAll(bytes.TrimSpace(msg.Bytes()), []byte{'\r'}, nil), []byte{'\n'}) {
		if len(line) < 1 {
			line = emptyLine
		}

		mustFprintf(buf, "PRIVMSG %s :", recipient)
		buf.Write(line)
		buf.WriteString("\r\n")
	}

	buf.WriteString("QUIT\r\n")

	dial := net.Dial
	if ssl {
		var tlsCfg *tls.Config
		if ircUrlQuery.Get("insecure") == "1" {
			tlsCfg = &tls.Config{InsecureSkipVerify: true}
		}

		dial = (&tls.Dialer{Config: tlsCfg}).Dial
	}

	host, port, errHP := net.SplitHostPort(ircUrl.Host)
	if errHP != nil {
		host = ircUrl.Host
		port = defaultPort
	}

	conn, errDl := dial("tcp", net.JoinHostPort(host, port))
	if errDl != nil {
		_, _ = fmt.Fprintln(os.Stderr, errDl.Error())
		return 1
	}

	defer func() { _ = conn.Close() }()

	if _, err := io.Copy(conn, buf); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}

	if _, err := io.Copy(os.Stdout, conn); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		return 1
	}

	return exitSuccess
}

func empty(s string) bool {
	return strings.TrimSpace(s) == ""
}

func complain(msg string) {
	_, _ = fmt.Fprintln(os.Stderr, msg)
	os.Exit(2)
}

func mustFprintf(w io.Writer, format string, a ...interface{}) {
	if _, err := fmt.Fprintf(w, format, a...); err != nil {
		panic(err)
	}
}
