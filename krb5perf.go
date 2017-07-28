package main

import (
	"github.com/alexflint/go-arg"
	"github.com/zephyr-im/krb5-go"
	"log"
	"os"
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

	credential, err := ctx.GetInitialCredentialWithKeyTab(keytab, client, service)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Got credential\n")
	log.Printf("\tClient = %v\n", credential.Client)
	log.Printf("\tServer = %v\n", credential.Server)
	log.Printf("\tAuthTime = %v\n", credential.AuthTime())
	log.Printf("\tStartTime = %v\n", credential.StartTime())
	log.Printf("\tEndTime = %v\n", credential.EndTime())
	log.Printf("\tKeyBlock = %v\n", credential.KeyBlock)
	log.Printf("\n")
	log.Printf("raw credential = %v\n", credential)
	log.Printf("\n")
	log.Printf("\n")
}
