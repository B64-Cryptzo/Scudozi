package main

import (
	"flag"
	"log"
	"os"
	"scudozi/internal/server"
	"strconv"
)

func main() {
	demoServices := flag.Bool("demo-services", false, "Inject synthetic demo services into the graph")
	demoCount := flag.Int("demo-services-count", 4, "How many demo services to inject (1-8)")
	logFile := flag.String("log-file", "", "Audit log file path (default: ./scudozi.log)")
	logStdout := flag.Bool("log-stdout", false, "Also print audit logs to stdout (noisier)")
	flag.Parse()

	if *demoServices {
		_ = os.Setenv("SCUDOZI_DEMO_SERVICES", "1")
	}
	if *demoCount > 0 {
		_ = os.Setenv("SCUDOZI_DEMO_SERVICES_COUNT", strconv.Itoa(*demoCount))
	}
	if *logFile != "" {
		_ = os.Setenv("SCUDOZI_LOG_FILE", *logFile)
	}
	if *logStdout {
		_ = os.Setenv("SCUDOZI_LOG_STDOUT", "1")
	}

	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}
