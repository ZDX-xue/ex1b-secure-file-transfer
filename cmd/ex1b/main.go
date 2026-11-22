package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"ex1b/internal/console"
	"ex1b/internal/identity"
	"ex1b/internal/service"
	"ex1b/internal/transfer"
	"ex1b/internal/ui"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("用法: ex1b init | server | client | version")
	}
	options := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "init":
		dir := options.String("dir", "demo", "演示配置和数据目录")
		listen := options.String("listen", "127.0.0.1:43951", "文件传输服务地址")
		name := options.String("server-name", "", "证书额外包含的服务端名称")
		if err := options.Parse(args[1:]); err != nil {
			return err
		}
		if err := identity.InitDemo(*dir, *listen, *name); err != nil {
			return err
		}
		fmt.Printf("已建立 %s 中的演示配置和证书。\n", *dir)
	case "server":
		path := options.String("config", "demo/server.json", "服务端配置")
		consoleListen := options.String("console", "127.0.0.1:43950", "服务端管理页地址")
		if err := options.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := identity.LoadServer(*path)
		if err != nil {
			return err
		}
		return serve(ctx, cfg, *consoleListen)
	case "client":
		path := options.String("config", "demo/alice.json", "客户端配置")
		if err := options.Parse(args[1:]); err != nil {
			return err
		}
		cfg, err := identity.LoadClient(*path)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(cfg.Downloads, 0700); err != nil {
			return err
		}
		engine, err := transfer.New(ctx, cfg)
		if err != nil {
			return err
		}
		defer engine.Drop()
		return ui.Serve(ctx, cfg.UIListen, cfg.Downloads, engine, func(url string) {
			fmt.Printf("客户端传输页  %s\n", url)
			fmt.Printf("下载目录  %s\n", cfg.Downloads)
		})
	case "version":
		fmt.Println("EX1B 1.0 · TLS file transfer")
	default:
		return fmt.Errorf("未知命令 %q，请使用 init、server 或 client", args[0])
	}
	return nil
}

func serve(parent context.Context, cfg identity.ServerConfig, consoleListen string) error {
	svc, err := service.New(cfg)
	if err != nil {
		return err
	}
	defer svc.Close()
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	errs := make(chan error, 2)
	go func() { errs <- svc.Serve(ctx, listener) }()
	go func() {
		errs <- console.Serve(ctx, consoleListen, svc, func(url string) {
			fmt.Printf("服务端管理页  %s\n", url)
			fmt.Printf("加密传输地址  %s\n", listener.Addr())
		})
	}()
	first := <-errs
	cancel()
	return errors.Join(first, <-errs)
}
