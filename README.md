Kerberos v5 "performance" tool.

## Installation
`$ go get github.com/cobaugh/krb5perf`

## Build
Note: go-krb5 does not appear to work on FreeBSD 11.x at the moment. Building should work fine on Linux as long as your `krb5-devel` or equivalent package providing krb5.h is installed.

```
$ go get -d ./...
$ go build
```

## Usage
```
$ ./krb5perf -h
./krb5perf krb5perf 0.1
Usage: krb5perf --keytab KEYTAB --client CLIENT --service SERVICE --iterations ITERATIONS --parallelism PARALLELISM

Options:
  --keytab KEYTAB, -k KEYTAB
  --client CLIENT, -c CLIENT
  --service SERVICE, -s SERVICE
  --iterations ITERATIONS, -i ITERATIONS
  --parallelism PARALLELISM, -p PARALLELISM
  --help, -h             display this help and exit
  --version              display version and exit
```

## Example output
Normal operation, no errors:
```
$ KRB5_CONFIG=./krb5.conf ./krb5perf --keytab ./atcldtst.keytab --client atcldtst@dce-acc.psu.edu --service krbtgt/dce-acc.psu.edu -i 10 -p 2
2017/07/31 10:28:38 [1] 13.235536ms AS_REQ SUCCESS
2017/07/31 10:28:38 [2] 13.519386ms AS_REQ SUCCESS
2017/07/31 10:28:38 [1] 2.000694ms AS_REQ SUCCESS
2017/07/31 10:28:38 [2] 1.988414ms AS_REQ SUCCESS
2017/07/31 10:28:38 [1] 1.916212ms AS_REQ SUCCESS
2017/07/31 10:28:38 [2] 1.91963ms AS_REQ SUCCESS
2017/07/31 10:28:38 [1] 2.093458ms AS_REQ SUCCESS
2017/07/31 10:28:38 [2] 2.071232ms AS_REQ SUCCESS
2017/07/31 10:28:38 [1] 1.990019ms AS_REQ SUCCESS
2017/07/31 10:28:38 [2] 1.981982ms AS_REQ SUCCESS

===========
Total elapsed time: 21.814994ms
Parallelism: 2, SUCCESS/FAIL: 10/0
SUCCESS: avg: 4.271656ms, max: 13.519386ms, min: 1.916212ms, 99pct: 13.377461ms, 95pct: 13.377461ms
FAIL: avg: 0s, max: 0s, min: 0s, 99pct: 0s, 95pct: 0s
Errors:
```

Errors are encountered:
```
$ KRB5_CONFIG=./krb5.conf ./krb5perf --keytab ./atcldtst.keytab --client atcldtst@dce-acc.psu.edu --service krbtgt/dce-acc.psu.edu2 -i 10 -p 2                                    
2017/07/31 10:06:49 [2] 3.885317ms AS_REQ FAIL (Server not found in Kerberos database)
2017/07/31 10:06:49 [1] 3.889256ms AS_REQ FAIL (Server not found in Kerberos database)
2017/07/31 10:06:49 [1] 3.149532ms AS_REQ FAIL (Server not found in Kerberos database)
2017/07/31 10:06:49 [2] 3.234567ms AS_REQ FAIL (Server not found in Kerberos database)
2017/07/31 10:06:49 [2] 3.042234ms AS_REQ FAIL (Server not found in Kerberos database)
2017/07/31 10:06:49 [1] 3.200941ms AS_REQ FAIL (Server not found in Kerberos database)
2017/07/31 10:06:49 [1] 2.93091ms AS_REQ FAIL (Server not found in Kerberos database)
2017/07/31 10:06:49 [2] 3.110518ms AS_REQ FAIL (Server not found in Kerberos database)
2017/07/31 10:06:49 [1] 3.133305ms AS_REQ FAIL (Server not found in Kerberos database)
2017/07/31 10:06:49 [2] 3.138918ms AS_REQ FAIL (Server not found in Kerberos database)

===========
Total elapsed time: 16.844693ms
Parallelism: 2, SUCCESS/FAIL: 0/10
SUCCESS: avg: 0s, max: 0s, min: 0s, 99pct: 0s, 95pct: 0s
FAIL: avg: 3.271549ms, max: 3.889256ms, min: 2.93091ms, 99pct: 3.887286ms, 95pct: 3.887286ms
Errors:
10      Server not found in Kerberos database
```

## TODO
[ ] Hide the request output unless user asks to see it, otherwise display a running percent complete 
[ ] Add support for user-defined delay, and random delay to simulate more realistic workloads
[x] Allow password auth
[ ] Allow reading users/passwords in from a file, and allow to sort them and use them in order when generating requests
