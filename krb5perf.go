// krb5perf is a tool to perform performance benchmarking and stress testing of Kerberos v5 KDC AS_REQ functions
package main

import (
	"container/ring"
	"encoding/csv"
	"fmt"
	"github.com/alexflint/go-arg"
	"github.com/cobaugh/krb5-go"
	"github.com/montanaflynn/stats"
	"io"
	"log"
	"os"
	"time"
)

// arguments
type Args struct {
	Keytab      string `arg:"env:KTNAME,-k"`
	Client      string `arg:"-c"`
	Csv         string `arg:"-C,help:CSV file containing records of the form client\,password"`
	Password    string `arg:"-P"`
	Service     string `arg:"-s,required"`
	Iterations  int    `arg:"-i,required"`
	Parallelism int    `arg:"-p,required"`
}

// durations is a slice of time.Durations
type durations []time.Duration

// an authentication request
type authrequest struct {
	client  authclient
	service string
}

// an authentication result
type authresult struct {
	success bool
	err     error
	elapsed time.Duration
}

//
type authclient struct {
	principal string
	password  string
	keytab    *krb5.KeyTab
}

func (Args) Version() string {
	return os.Args[0] + " krb5perf 0.1"
}

func main() {
	var args Args
	arg.MustParse(&args)

	// create a shared context
	ctx, err := krb5.NewContext()
	if err != nil {
		log.Fatal(err)
	}

	var authclientr *ring.Ring

	// check for keytab, password, or csv file arguments
	if args.Keytab != "" {
		keytab, err := ctx.OpenKeyTab(args.Keytab)
		if err != nil {
			log.Fatal(err)
		}
		defer keytab.Close()
		authclientr = ringFromSlice([]authclient{authclient{principal: args.Client, password: "", keytab: keytab}})
		log.Printf("Using keytab at '%s' to authenticate", args.Keytab)
	} else if args.Password != "" {
		authclientr = ringFromSlice([]authclient{authclient{principal: args.Client, password: args.Password, keytab: nil}})
		log.Print("Using password to authenticate")
	} else if args.Csv != "" {
		csvclients, err := clientsFromCsvFile(args.Csv)
		if err != nil {
			log.Fatal(err)
		}
		authclientr = ringFromSlice(csvclients)
	} else {
		log.Fatal("One of either --password or --keytab must be specified")
	}

	authrequestc := make(chan authrequest, args.Iterations)
	authresultc := make(chan authresult, args.Iterations)

	// create workers
	for i := 1; i <= args.Parallelism; i++ {
		go authworker(i, authrequestc, authresultc)
	}

	// submit jobs
	start := time.Now()
	for i := 1; i <= args.Iterations; i++ {
		c := authclientr.Value
		authrequestc <- authrequest{client: c.(authclient), service: args.Service}
		authclientr = authclientr.Next()
	}

	// collect results
	var s durations
	var f durations
	var errors = make(map[string]int)
	for i := 1; i <= args.Iterations; i++ {
		r := <-authresultc
		if r.success {
			s = append(s, r.elapsed)
		} else {
			f = append(f, r.elapsed)
			errors[r.err.Error()]++
		}
	}
	elapsed := time.Since(start)

	var error_report string
	for e, i := range errors {
		error_report += fmt.Sprintf("%d\t%s\n", i, e)
	}

	fmt.Printf("\n===========\n"+
		"Total elapsed time: %s\n"+
		"Average req/s: %.2f\n"+
		"Parallelism: %d, SUCCESS/FAIL: %d/%d\n"+
		"SUCCESS: avg: %s, max: %s, min: %s, 99pct: %s, 95pct: %s\n"+
		"FAIL: avg: %s, max: %s, min: %s, 99pct: %s, 95pct: %s\n"+
		"Errors:\n%s",
		elapsed,
		float64(args.Iterations)/elapsed.Seconds(),
		args.Parallelism, len(s), len(f),
		s.dstat(stats.Mean), s.dstat(stats.Max), s.dstat(stats.Min), s.dpct(stats.Percentile, 99), s.dpct(stats.Percentile, 95),
		f.dstat(stats.Mean), f.dstat(stats.Max), f.dstat(stats.Min), f.dpct(stats.Percentile, 99), f.dpct(stats.Percentile, 95),
		error_report,
	)

}

// read all records from the given CSV file, and return them as a slice of client
func clientsFromCsvFile(filename string) ([]authclient, error) {
	var clients []authclient

	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		return nil, err
	}

	reader := csv.NewReader(file)
	for {
		r, err := reader.Read()
		if err == io.EOF {
			return clients, nil
		} else if err != nil {
			return nil, err
		}
		clients = append(clients, authclient{principal: r[0], password: r[1], keytab: nil})
	}
}

// takes a slice and returns a ring
func ringFromSlice(s []authclient) *ring.Ring {
	r := ring.New(len(s))
	for i := 0; i < r.Len(); i++ {
		r.Value = s[i]
		r = r.Next()
	}
	return r
}

// Given durations, convert each duration to a float64 and run the given stats function on the resulting float64s
func (d durations) dstat(f func(stats.Float64Data) (float64, error)) time.Duration {
	dfloat := make([]float64, len(d))
	for i, v := range d {
		dfloat[i] = float64(v)
	}

	s, err := f(dfloat)
	if err != nil {
		return 0
	} else {
		return time.Duration(s)
	}
}

// Given durations, convert each duration to a float64 and run the given stats percentile function on the resulting float64s
func (d durations) dpct(f func(stats.Float64Data, float64) (float64, error), p float64) time.Duration {
	dfloat := make([]float64, len(d))
	for i, v := range d {
		dfloat[i] = float64(v)
	}

	s, err := f(dfloat, p)
	if err != nil {
		return 0
	} else {
		return time.Duration(s)
	}
}

// worker function
func authworker(w int, authrequestc <-chan authrequest, authresultc chan<- authresult) {
	for a := range authrequestc {
		success := true
		status := "SUCCESS"

		// set up our context
		ctx, err := krb5.NewContext()
		if err != nil {
			log.Fatal(err)
		}

		client, err := ctx.ParseName(a.client.principal)
		if err != nil {
			log.Fatal(err)
		}

		service, err := ctx.ParseName(a.service)
		if err != nil {
			log.Fatal(err)
		}

		start := time.Now()
		if a.client.password != "" {
			_, err = ctx.GetInitialCredentialWithPassword(a.client.password, client, service)
		} else {
			_, err = ctx.GetInitialCredentialWithKeyTab(a.client.keytab, client, service)
		}
		elapsed := time.Since(start)

		ctx.Free()

		if err != nil {
			status = fmt.Sprintf("FAIL (%s)", err)
			success = false
		}
		log.Printf("[%d] %s AS_REQ (%s) %s", w, elapsed, a.client.principal, status)

		authresultc <- authresult{
			success: success,
			err:     err,
			elapsed: elapsed,
		}

	}
}
