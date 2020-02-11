package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/rds"
	flag "github.com/jessevdk/go-flags"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"

	"github.com/honeycombio/libhoney-go"
	"github.com/honeycombio/rdslogs/cli"
)

var awsHTTPRequestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "aws_http_requests_total",
		Help: "The total number of requests to the AWS API, broken by status code, method, host and action",
	},
	[]string{"code", "method", "host", "action", "database"},
)

// BuildID is set by Travis CI
var BuildID string

// ReqCounterMiddleware counters the number of requests
type ReqCounterMiddleware struct {
	Proxied http.RoundTripper
}

// RoundTrip implements the RoundTripper interface.
func (m ReqCounterMiddleware) RoundTrip(r *http.Request) (resp *http.Response, err error) {
	hostname := r.URL.Hostname()

	var (
		data   []byte
		body   string
		values url.Values
	)

	if r.Body != nil {
		data, _ = ioutil.ReadAll(r.Body)
	}

	body = string(data)

	// For RDS API calls, the body is actually a query string, like:
	// Action=DownloadDBLogFilePortion&DBInstanceIdentifier=insider-prod&LogFileName...
	values, _ = url.ParseQuery(body)

	// Restore the io.ReadCloser to its original state
	r.Body = ioutil.NopCloser(bytes.NewBuffer(data))

	action, ok := values["Action"]
	database, ok := values["DBInstanceIdentifier"]

	if !ok {
		database = []string{"nil"}
	}

	if !ok {
		action = []string{"nil"}
	}

	logrus.WithFields(logrus.Fields{
		"host":     hostname,
		"path":     r.URL.Path,
		"query":    r.URL.RawQuery,
		"body":     body,
		"values":   values,
		"action":   action,
		"database": database,
	}).Debugln("sending AWS API request")

	// Send the request, get the response
	resp, err = m.Proxied.RoundTrip(r)

	var statusCode string

	if err != nil {
		statusCode = "000"

		logrus.WithFields(logrus.Fields{
			"host":  hostname,
			"path":  r.URL.Path,
			"query": r.URL.RawQuery,
		}).WithError(err).Errorln("error performing AWS API request")
	}

	if resp != nil {
		statusCode = strconv.Itoa(resp.StatusCode)
	}

	awsHTTPRequestsTotal.WithLabelValues(
		statusCode,
		r.Method,
		hostname,
		strings.Join(action, ","),
		strings.Join(database, ","),
	).Inc()

	return
}

func main() {
	options, err := parseFlags()
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/metrics", promhttp.Handler())

	go func() {
		fmt.Println("exposing Prometheus metrics at 0.0.0.0:3000/metrics")
		log.Fatal(http.ListenAndServe(":3000", nil))
	}()

	sigs := make(chan os.Signal, 1)
	abort := make(chan bool, 0)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		fmt.Fprintf(os.Stderr, "Aborting! Caught Signal \"%s\"\n", sig)
		fmt.Fprintf(os.Stderr, "Cleaning up...\n")
		select {
		case abort <- true:
			close(abort)
		case <-time.After(10 * time.Second):
			fmt.Fprintf(os.Stderr, "Taking too long... Aborting.\n")
			os.Exit(1)
		}
	}()

	sess := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(options.Region),
		// default retry is set to 0
		// add custom retry parameters to avoid throttling erros
		Retryer: client.DefaultRetryer{
			NumMaxRetries:    options.BackoffMaxRetries,
			MinRetryDelay:    50 * time.Millisecond,
			MaxRetryDelay:    3000 * time.Millisecond,
			MinThrottleDelay: time.Duration(options.BackoffTimer),
			MaxThrottleDelay: 5 * time.Duration(options.BackoffTimer) * time.Second,
		},
		HTTPClient: &http.Client{
			Transport: ReqCounterMiddleware{http.DefaultTransport},
		},
	}))

	c := &cli.CLI{
		Options: options,
		RDS:     rds.New(sess),
		Abort:   abort,
	}

	if options.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	// if sending output to Honeycomb, make sure we have a write key and dataset
	if options.Output == "honeycomb" {
		if options.WriteKey == "" || options.Dataset == "" {
			log.Fatal("writekey and dataset flags required when output is 'honeycomb'.\nuse --help for usage info.")
		}
		if options.SampleRate < 1 {
			log.Fatal("Sample rate must be a positive integer.\nuse --help for usage info.")
		}
		libhoney.UserAgentAddition = fmt.Sprintf("rdslogs/%s", BuildID)
		fmt.Fprintln(os.Stderr, "Sending output to Honeycomb")
	} else if options.Output == "stdout" {
		fmt.Fprintln(os.Stderr, "Sending output to STDOUT")
	} else {
		// output flag is neither stdout nor honeycomb.  error and bail
		log.Fatal("output target not recognized. use --help for usage info")
	}

	// make sure we can talk to an RDS instance.
	err = c.ValidateRDSInstance()
	if err == credentials.ErrNoValidProvidersFoundInChain {
		log.Fatal(awsCredsFailureMsg())
	}
	if err != nil {
		log.Fatal(err)
	}

	if options.Download {
		fmt.Fprintln(os.Stderr, "Running in download mode - downloading old logs")
		err = c.Download()
	} else {
		fmt.Fprintln(os.Stderr, "Running in tail mode - streaming logs from RDS")
		err = c.Stream()
	}
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(os.Stderr, "OK")
}

// getVersion returns the internal version ID
func getVersion() string {
	if BuildID == "" {
		return "dev"
	}
	return fmt.Sprintf("%s", BuildID)
}

// parse all the flags, exit if anything's amiss
func parseFlags() (*cli.Options, error) {
	var options cli.Options
	flagParser := flag.NewParser(&options, flag.Default)
	flagParser.Usage = cli.Usage

	// parse flags and check for extra command line args
	if extraArgs, err := flagParser.Parse(); err != nil || len(extraArgs) != 0 {
		if err != nil {
			if err.(*flag.Error).Type == flag.ErrHelp {
				// user specified --help
				os.Exit(0)
			}
			fmt.Fprintln(os.Stderr, "Failed to parse the command line. Run with --help for more info")
			return nil, err
		}
		return nil, fmt.Errorf("unexpected extra arguments: %s", strings.Join(extraArgs, " "))
	}

	// if all we want is the config file, just write it in and exit
	if options.WriteDefaultConfig {
		ip := flag.NewIniParser(flagParser)
		ip.Write(os.Stdout, flag.IniIncludeDefaults|flag.IniCommentDefaults|flag.IniIncludeComments)
		os.Exit(0)
	}

	// spit out the version if asked
	if options.Version {
		fmt.Println("Version:", getVersion())
		os.Exit(0)
	}
	// read the config file if specified
	if options.ConfigFile != "" {
		ini := flag.NewIniParser(flagParser)
		ini.ParseAsDefaults = true
		if err := ini.ParseFile(options.ConfigFile); err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("config file %s doesn't exist", options.ConfigFile)
			}
			return nil, err
		}
	}

	if options.DBType == cli.DBTypeMySQL && options.LogType == cli.LogTypeQuery {
		if options.LogFile == "" {
			options.LogFile = "slowquery/mysql-slowquery.log"
		}
	} else if options.DBType == cli.DBTypeMySQL && options.LogType == cli.LogTypeAudit {
		if options.LogFile == "" {
			options.LogFile = "audit/server_audit.log"
		}
	} else if options.DBType == cli.DBTypePostgreSQL && options.LogType == cli.LogTypeQuery {
		if options.LogFile == "" {
			options.LogFile = "error/postgresql.log"
		}
	} else {
		return nil, fmt.Errorf(
			"Unsupported (dbtype, log_type) pair (`%s`,`%s`)",
			options.DBType, options.LogType)
	}
	return &options, nil
}

func awsCredsFailureMsg() string {
	// check for AWS binary
	_, err := exec.LookPath("aws")
	if err == nil {
		return `Unable to locate credentials. You can configure credentials by running "aws configure".`
	}
	return `Unable to locate AWS credentials. You have a few options:
- Create an IAM role for the host machine with the permissions to access RDS
- Use an AWS shared config file (~/.aws/config)
- Configure credentials on a development machine (via ~/.aws/credentials)
- Or set the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables

You can read more at this security blog post:
http://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs

Or read more about IAM roles and RDS at:
http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAM.AccessControl.IdentityBased.html`
}
