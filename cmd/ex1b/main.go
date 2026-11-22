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
	"ex1b/internal/webapp"
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
		return errors.New("用法: ex1b web | init | server | client | version")
	}
	options := flag.NewFlagSet(args[0], flag.ContinueOnError)
	switch args[0] {
	case "web":
		var web webapp.Options
		options.StringVar(&web.Listen, "listen", "127.0.0.1:4443", "Web 监听地址")
		options.StringVar(&web.Origin, "origin", "https://localhost:4443", "浏览器访问地址，亦用于证书和同源校验")
		options.IntVar(&web.AdminPort, "admin-port", 0, "独立管理员入口端口，0 表示关闭")
		options.StringVar(&web.UserPorts, "user-ports", "", "逗号分隔的独立用户入口端口")
		options.StringVar(&web.Data, "data", "web-data", "Web 账号、文件与 PKI 数据目录")
		options.StringVar(&web.AdminPasswordFile, "admin-password-file", "", "首次初始化管理员密码的文件")
		if err := options.Parse(args[1:]); err != nil {
			return err
		}
		web.Ready = func(origins []string, caFile, passFile string) {
			fmt.Printf("EX1B Web  %s\n", origins[0])
			for _, origin := range origins[1:] {
				fmt.Printf("独立登录入口  %s\n", origin)
			}
			fmt.Printf("实验 CA  %s\n首次管理员 admin 的密码文件  %s\n", caFile, passFile)
		}
		return webapp.Run(ctx, web)
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
		return fmt.Errorf("未知命令 %q，请使用 web、init、server 或 client", args[0])
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
