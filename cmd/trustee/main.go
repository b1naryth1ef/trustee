package main

import (
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/b1naryth1ef/trustee"
	"github.com/spf13/viper"
)

func main() {
	viper.SetConfigName("config")
	viper.AddConfigPath(".")
	viper.AutomaticEnv()

	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)
	viper.ReadInConfig()

	server, err := trustee.NewServer()
	if err != nil {
		panic(err)
	}

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigc
		log.Printf("Caught signal %s: shutting down.", sig)
		server.Close()
		os.Exit(0)
	}()

	server.Run()
}
