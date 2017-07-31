package main

import (
	"fmt"
	"github.com/alexflint/go-arg"
	"github.com/montanaflynn/stats"
	"github.com/zephyr-im/krb5-go"
	"log"
	"os"
	"time"
)

type Args struct {
	Keytab      string `arg:"env:KTNAME,-k,required"`
	Client      string `arg:"-c,required"`
	Service     string `arg:"-s,required"`
	Iterations  int    `arg:"-i,required"`
	Parallelism int    `arg:"-p,required"`
}

type durations []time.Duration

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

	// create workers
	for i := 1; i <= args.Parallelism; i++ {
		go authworker(i, authrequestc, authresultc)
	}

	// submit jobs
	start := time.Now()
	for i := 1; i <= args.Iterations; i++ {
		authrequestc <- authrequest{keytab: keytab, client: args.Client, service: args.Service}
	}

	// collect results
	var s durations
	var f durations
	var errors = make(map[error]int)
	for i := 1; i <= args.Iterations; i++ {
		r := <-authresultc
		if r.success {
			s = append(s, r.elapsed)
		} else {
			f = append(f, r.elapsed)
			errors[r.err]++
		}
	}
	elapsed := time.Since(start)

	var error_report string
	for e, i := range errors {
		error_report += fmt.Sprintf("%d\t%s\n", i, e)
	}

	fmt.Printf("\n===========\n"+
		"Total elapsed time: %s\n"+
		"Parallelism: %d, SUCCESS/FAIL: %d/%d\n"+
		"SUCCESS: avg: %s, max: %s, min: %s, 99pct: %s, 95pct: %s\n"+
		"FAIL: avg: %s, max: %s, min: %s, 99pct: %s, 95pct: %s\n"+
		"Errors:\n%s",
		elapsed,
		args.Parallelism, len(s), len(f),
		s.dstat(stats.Mean), s.dstat(stats.Max), s.dstat(stats.Min), s.dpct(stats.Percentile, 99), s.dpct(stats.Percentile, 95),
		f.dstat(stats.Mean), f.dstat(stats.Max), f.dstat(stats.Min), f.dpct(stats.Percentile, 99), f.dpct(stats.Percentile, 95),
		error_report,
	)

}

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
