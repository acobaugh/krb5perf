package main

import (
	"fmt"
	"github.com/alexflint/go-arg"
	"github.com/zephyr-im/krb5-go"
	"log"
	"os"
	"time"
)

// Usage: krb5perf.pl -k <keytab> -c <client princ> -s <server princ> -i <iterations> -p <parallelism> -h
type Args struct {
	KeytabFile  string `arg:"env:KTNAME,-k"`
	Client      string `arg:"-c"`
	Service     string `arg:"-s"`
	Iterations  int    `arg:"-i"`
	Parallelism int    `arg:"-p"`
}

func (Args) Version() string {
	return os.Args[0] + " krb5perf 0.1"
}

func main() {
	var args Args
	arg.MustParse(&args)

	ctx, err := krb5.NewContext()
	if err != nil {
		log.Fatal(err)
	}
	defer ctx.Free()

	keytab, err := ctx.OpenKeyTab(args.KeytabFile)
	if err != nil {
		log.Fatal(err)
	}
	defer keytab.Close()

	client, err := ctx.ParseName(args.Client)
	if err != nil {
		log.Fatal(err)
	}

	service, err := ctx.ParseName(args.Service)
	if err != nil {
		log.Fatal(err)
	}

	doAS_REQ(ctx, keytab, client, service)
}

func doAS_REQ(ctx *krb5.Context, keytab *krb5.KeyTab, client *krb5.Principal, service *krb5.Principal) error {
	status := "SUCCESS"

	start := time.Now()
	_, err := ctx.GetInitialCredentialWithKeyTab(keytab, client, service)
	if err != nil {
		status = fmt.Sprintf("FAIL (%s)", err)
	}

	timeTrack(start, "AS_REQ "+status)
	return nil
}

func timeTrack(start time.Time, name string) {
	elapsed := time.Since(start)
	log.Printf("%s %s", elapsed, name)
}
