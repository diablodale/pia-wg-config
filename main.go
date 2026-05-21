package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	cli "github.com/urfave/cli/v2"
	"pia-wg-config/pia"
)

// version is stamped at build time via: -ldflags "-X main.version=$(git describe --tags)"
var version = "dev"

func main() {
	// urfave/cli registers -v as a short alias for --version by default, which
	// conflicts with our -v/--verbose flag. Override to long-form only.
	cli.VersionFlag = &cli.BoolFlag{Name: "version", Usage: "print the version"}

	app := &cli.App{
		Name:    "pia-wg-config",
		Version: version,
		Usage:   "generate a wireguard config for private internet access",
		Description: "Credentials can be supplied as positional arguments (USERNAME PASSWORD) or via\n" +
			"the PIAWGCONFIG_USER and PIAWGCONFIG_PW environment variables (recommended).\n" +
			"Environment variables take priority over positional arguments.",
		Action: defaultAction,

		Commands: []*cli.Command{
			{
				Name:    "regions",
				Aliases: []string{"r"},
				Usage:   "List available PIA regions. Use --port-forward to limit to regions that support port forwarding.",
				Action:  listRegions,
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "port-forward",
						Usage: "Only show regions that support port forwarding",
					},
				},
			},
			{
				Name:  "port-forward",
				Usage: "Bind and keep alive a PIA port forward (run after the WireGuard tunnel is up)",
				Description: "Reads the port-forward state file written during config generation, calls\n" +
					"/getSignature to obtain an assigned port, then calls /bindPort every 15 minutes\n" +
					"to keep the forwarded port alive. The tunnel must be active before running this.",
				Action: portForwardAction,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "pf-state-file",
						Aliases:  []string{"s"},
						Usage:    "Port-forward state `FILE` written by config generation (required)",
						Required: true,
					},
					&cli.StringFlag{
						Name:    "ca-cert",
						Aliases: []string{"c"},
						Usage:   "Path to PIA CA cert pem `FILE` (optional, auto-downloaded if omitted)",
					},
					&cli.BoolFlag{
						Name:    "verbose",
						Aliases: []string{"v"},
						Usage:   "Print verbose output",
					},
				},
			},
		},

		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "outfile",
				Aliases: []string{"o"},
				Usage:   "Write the Wireguard config to `FILE`. If omitted, the config is printed to stdout.",
			},
			&cli.StringFlag{
				Name:    "region",
				Aliases: []string{"r"},
				Value:   "us_california",
				Usage:   "Private Internet Access region to connect to (use 'regions' command to list all available regions)",
			},
			&cli.BoolFlag{
				Name:    "verbose",
				Aliases: []string{"v"},
				Value:   false,
				Usage:   "Print verbose output",
			},
			&cli.StringFlag{
				Name:    "ca-cert",
				Aliases: []string{"c"},
				Usage:   "Path to a locally-trusted PIA ca cert pem `FILE`. If omitted, the cert is fetched from GitHub and verified against a pinned SHA-256 fingerprint.",
			},
			&cli.StringFlag{
				Name:    "pf-state-file",
				Aliases: []string{"s"},
				Usage:   "Save port-forward state to `FILE` for use with the 'port-forward' command after connecting",
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func defaultAction(c *cli.Context) error {
	// Credentials: env vars take priority, positional args are fallback.
	username := os.Getenv("PIAWGCONFIG_USER")
	if username == "" {
		username = c.Args().Get(0)
	}
	password := os.Getenv("PIAWGCONFIG_PW")
	if password == "" {
		password = c.Args().Get(1)
	}

	if username == "" || password == "" {
		fmt.Println("Error: PIA username and password are required but were not provided.")
		fmt.Println()
		fmt.Println("Provide credentials via environment variables (recommended):")
		fmt.Println("  PIAWGCONFIG_USER=user PIAWGCONFIG_PW=pass pia-wg-config [OPTIONS]")
		fmt.Println()
		fmt.Println("Or as positional arguments:")
		fmt.Println("  pia-wg-config [OPTIONS] USERNAME PASSWORD")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  pia-wg-config myuser mypass")
		fmt.Println("  PIAWGCONFIG_USER=alice PIAWGCONFIG_PW=secret pia-wg-config -r uk_london")
		fmt.Println("  pia-wg-config -r de_frankfurt -o config.conf myuser mypass")
		fmt.Println()
		fmt.Println("To see available regions:")
		fmt.Println("  pia-wg-config regions")
		return cli.Exit("", 1)
	}

	// PIA usernames are always 'p' followed by digits (e.g. p1234567).
	// Normalise to lowercase first so 'P1234567' is also accepted.
	// Validated against PIA's own tooling: https://github.com/pia-foss/manual-connections
	username = strings.ToLower(username)
	if !regexp.MustCompile(`^p\d+$`).MatchString(username) {
		fmt.Println("Error: PIA username must start with 'p' followed by digits (e.g. p1234567).")
		return cli.Exit("", 1)
	}

	verbose := c.Bool("verbose")
	region := c.String("region")
	caCertPath := c.String("ca-cert")
	pfStateFile := c.String("pf-state-file")

	// Capture PF state inside the callback so Generate() can pass it back.
	var pfState *pia.PortForwardState
	var onPFStateReady func(token, serverCN, serverVip string)
	if pfStateFile != "" {
		onPFStateReady = func(token, serverCN, serverVip string) {
			pfState = &pia.PortForwardState{
				Token:     token,
				ServerCN:  serverCN,
				ServerVip: serverVip,
			}
		}
	}

	// create pia client
	if verbose {
		if c.IsSet("region") {
			log.Printf("Region: %s (user-specified)", region)
		} else {
			log.Printf("Region: %s (default; use --region to override)", region)
		}
	}
	piaClient, err := pia.NewPIAClient(username, password, region, caCertPath, verbose)
	if err != nil {
		if verbose {
			log.Printf("Failed to create PIA client: %v", err)
		}
		fmt.Printf("Error: Failed to connect to PIA servers\n")
		fmt.Printf("This could be due to:\n")
		fmt.Printf("  - Invalid username or password\n")
		fmt.Printf("  - Invalid region '%s' (run 'pia-wg-config regions' to see available regions)\n", region)
		fmt.Printf("  - Network connectivity issues\n")
		fmt.Printf("  - PIA service unavailable\n")
		fmt.Printf("\nTry running with -v flag for more details\n")
		return cli.Exit("", 1)
	}

	// create wg config generator
	if verbose {
		log.Print("creating wg config generator")
	}
	wgConfigGenerator := pia.NewPIAWgGenerator(piaClient, pia.PIAWgGeneratorConfig{
		Verbose:        verbose,
		OnPFStateReady: onPFStateReady,
	})

	// generate wg config
	if verbose {
		log.Print("Generating wireguard config")
	}
	config, err := wgConfigGenerator.Generate()
	if err != nil {
		if verbose {
			log.Printf("Failed to generate config: %v", err)
		}
		fmt.Printf("Error: Failed to generate Wireguard configuration\n")
		fmt.Printf("This could be due to:\n")
		fmt.Printf("  - Authentication failure (check your PIA credentials)\n")
		fmt.Printf("  - Server communication issues\n")
		fmt.Printf("  - Region server unavailable\n")
		fmt.Printf("\nTry running with -v flag for more details\n")
		return cli.Exit("", 1)
	}

	outfile := c.String("outfile")
	if outfile != "" {
		// write config to file
		err = os.WriteFile(outfile, []byte(config), 0600) // More secure permissions
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error: Failed to write config to file '%s': %v", outfile, err), 1)
		}
		if verbose {
			log.Printf("Wireguard config written to: %s", outfile)
		}
		fmt.Printf("✓ Wireguard config generated successfully: %s\n", outfile)
		fmt.Printf("You can now connect using: sudo wg-quick up %s\n", outfile)
	} else {
		// print config to stdout
		fmt.Println(config)
	}

	// Write port-forward state file if requested.
	if pfStateFile != "" && pfState != nil {
		data, err := json.Marshal(pfState)
		if err != nil {
			return cli.Exit(fmt.Sprintf("Error: Failed to encode port-forward state: %v", err), 1)
		}
		if err := os.WriteFile(pfStateFile, data, 0600); err != nil {
			return cli.Exit(fmt.Sprintf("Error: Failed to write port-forward state to '%s': %v", pfStateFile, err), 1)
		}
		if verbose {
			log.Printf("Port-forward state written to: %s", pfStateFile)
		}
		fmt.Printf("✓ Port-forward state saved: %s\n", pfStateFile)
		fmt.Printf("  After connecting, run: pia-wg-config port-forward --pf-state-file %s\n", pfStateFile)
	}

	return nil
}

func listRegions(c *cli.Context) error {
	portForwardOnly := c.Bool("port-forward")

	if portForwardOnly {
		fmt.Println("Fetching available regions from PIA (port-forwarding only)...")
	} else {
		fmt.Println("Fetching available regions from PIA...")
	}

	// Create a dummy client just to get the server list (no credentials or CA cert required)
	piaClient, err := pia.NewPIAClient("", "", "us_california", "", false)
	if err != nil {
		return fmt.Errorf("failed to fetch regions: %v", err)
	}

	regions, err := piaClient.GetAvailableRegions()
	if err != nil {
		return fmt.Errorf("failed to get regions: %v", err)
	}

	// Sort regions for consistent output
	var regionList []string
	for region, info := range regions {
		if portForwardOnly && !info.PortForward {
			continue
		}
		regionList = append(regionList, string(region))
	}
	sort.Strings(regionList)

	if portForwardOnly {
		fmt.Println("\nPIA regions with port forwarding:")
		fmt.Println("===================================")
	} else {
		fmt.Println("\nAvailable PIA regions:")
		fmt.Println("======================")
	}
	for _, region := range regionList {
		fmt.Printf("  %s\n", region)
	}
	fmt.Printf("\nTotal: %d regions available\n", len(regionList))
	fmt.Println("\nUsage example:")
	fmt.Println("  pia-wg-config -r uk_london USERNAME PASSWORD")

	return nil
}

func portForwardAction(c *cli.Context) error {
	pfStateFile := c.String("pf-state-file")
	caCertPath := c.String("ca-cert")
	verbose := c.Bool("verbose")

	// Read the port-forward state file written during config generation.
	data, err := os.ReadFile(pfStateFile)
	if err != nil {
		return cli.Exit(fmt.Sprintf("Error: Failed to read port-forward state file '%s': %v", pfStateFile, err), 1)
	}
	var state pia.PortForwardState
	if err := json.Unmarshal(data, &state); err != nil {
		return cli.Exit(fmt.Sprintf("Error: Failed to parse port-forward state file: %v", err), 1)
	}
	if state.Token == "" || state.ServerCN == "" || state.ServerVip == "" {
		return cli.Exit("Error: Port-forward state file is incomplete (missing token, server_cn, or server_vip)", 1)
	}

	piaClient, err := pia.NewPIAClientForPortForward(caCertPath, verbose)
	if err != nil {
		return cli.Exit(fmt.Sprintf("Error: Failed to initialise PIA client: %v", err), 1)
	}

	fmt.Printf("Requesting port-forward signature from %s (%s)...\n", state.ServerCN, state.ServerVip)
	payload, signature, err := piaClient.GetPortForwardSignature(state)
	if err != nil {
		return cli.Exit(fmt.Sprintf("Error: Failed to get port-forward signature: %v\n"+
			"Make sure the WireGuard tunnel is active before running this command.", err), 1)
	}

	pfPayload, err := pia.DecodePortForwardPayload(payload)
	if err != nil {
		return cli.Exit(fmt.Sprintf("Error: Failed to decode port-forward payload: %v", err), 1)
	}

	fmt.Printf("Assigned port %d (expires %s)\n", pfPayload.Port, pfPayload.ExpiresAt)
	fmt.Println("Binding port and keeping it alive (Ctrl-C to stop)...")

	// Bind immediately, then refresh every 15 minutes.
	for {
		if err := piaClient.BindPort(state, payload, signature); err != nil {
			fmt.Printf("Warning: bindPort failed: %v — retrying next cycle\n", err)
		} else {
			fmt.Printf("Bound port %d (refreshes %s)\n",
				pfPayload.Port, time.Now().Add(15*time.Minute).Format("15:04:05"))
		}
		time.Sleep(15 * time.Minute)
	}
}
