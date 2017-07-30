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
	Keytab      string `arg:"env:KTNAME,-k,required"`
	Client      string `arg:"-c,required"`
	Service     string `arg:"-s,required"`
	Iterations  int    `arg:"-i,required"`
	Parallelism int    `arg:"-p,required"`
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

	keytab, err := ctx.OpenKeyTab(args.Keytab)
	if err != nil {
		log.Fatal(err)
	}
	defer keytab.Close()

	authrequestc := make(chan authrequest, args.Iterations)
	authresultc := make(chan authresult, args.Iterations)

	var authresults = []authresult{}

	// create workers
	for i := 1; i <= args.Parallelism; i++ {
		go authworker(i, authrequestc, authresultc)
	}

	// submit jobs
	for i := 1; i <= args.Iterations; i++ {
		authrequestc <- authrequest{keytab: keytab, client: args.Client, service: args.Service}
	}

	// collect results
	for i := 1; i <= args.Iterations; i++ {
		authresults = append(authresults, <-authresultc)
	}
}

type authrequest struct {
	keytab  *krb5.KeyTab
	client  string
	service string
}

type authresult struct {
	success bool
	err     error
	elapsed time.Duration
}

func authworker(w int, authrequestc <-chan authrequest, authresultc chan<- authresult) {
	for a := range authrequestc {
		success := true
		status := "SUCCESS"

		// set up our context
		ctx, err := krb5.NewContext()
		if err != nil {
			log.Fatal(err)
		}

		client, err := ctx.ParseName(a.client)
		if err != nil {
			log.Fatal(err)
		}

		service, err := ctx.ParseName(a.service)
		if err != nil {
			log.Fatal(err)
		}

		start := time.Now()
		_, err = ctx.GetInitialCredentialWithKeyTab(a.keytab, client, service)
		elapsed := time.Since(start)

		ctx.Free()

		if err != nil {
			status = fmt.Sprintf("FAIL (%s)", err)
			success = false
		}
		log.Printf("[%d] %s AS_REQ %s", w, elapsed, status)

		authresultc <- authresult{
			success: success,
			err:     err,
			elapsed: elapsed,
		}
	}
}
