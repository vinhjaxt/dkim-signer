package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"os"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
)

type StrFlags []string

func (i *StrFlags) String() string {
	return strings.Join(*i, `,`)
}

func (i *StrFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var dkimHeaders StrFlags
var email = flag.String(`email`, `email.eml`, `Set email raw source path`)
var outEmail = flag.String(`output`, ``, `Set output email raw source path`)
var dkimPrivateKeyPEM = flag.String(`key`, `private_key.pem`, `Set DKIM Private Key PEM filepath`)
var dkimDomain = flag.String(`domain`, `example.org`, `Set DKIM domain`)
var dkimDnsSelector = flag.String(`selector`, `dkim`, `Set DKIM DNS Selector`)

var dkimSignOptions *dkim.SignOptions

func init() {
	flag.Var(&dkimHeaders, `header`, `Set include headers (multiple flag) in Signature`)
	flag.Parse()

	b, err := os.ReadFile(*dkimPrivateKeyPEM)
	if err != nil {
		log.Panicln(err)
	}

	block, _ := pem.Decode(b)
	dkimPrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Panicln(err)
	}

	dkimSignOptions = &dkim.SignOptions{
		Domain:                 *dkimDomain,
		Selector:               *dkimDnsSelector,
		Signer:                 dkimPrivateKey,
		BodyCanonicalization:   dkim.CanonicalizationRelaxed,
		HeaderCanonicalization: dkim.CanonicalizationRelaxed,
	}
	if len(dkimHeaders) != 0 {
		dkimSignOptions.HeaderKeys = dkimHeaders
	}
}

func DkimSign(eml io.Reader) (*bytes.Buffer, error) {
	var b bytes.Buffer
	err := dkim.Sign(&b, eml, dkimSignOptions)
	if err != nil {
		return nil, err
	}
	return &b, nil
}

func main() {
	b, err := os.ReadFile(*email)
	if err != nil {
		log.Panicln(err)
	}

	o, err := DkimSign(bytes.NewReader(b))
	if err != nil {
		log.Panicln(err)
	}

	if *outEmail == `` {
		os.Stdout.Write(o.Bytes())
	} else {
		os.WriteFile(*outEmail, o.Bytes(), os.ModePerm)
	}
}
