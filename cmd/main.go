package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path"
	"runtime"
	"syscall"
	"time"

	rotates "github.com/lestrrat-go/file-rotatelogs"
	"github.com/rifflock/lfshook"
	"github.com/sirupsen/logrus"

	"github.com/haolipeng/convert_tunnel_detector/pkg/api"
	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/pipeline"
	"github.com/haolipeng/convert_tunnel_detector/pkg/processor"
	"github.com/haolipeng/convert_tunnel_detector/pkg/sink"
	"github.com/haolipeng/convert_tunnel_detector/pkg/source"
)

func InitLogger(cfg *config.Config) error {
	// 使用配置文件中的设置
	formatter := &logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: cfg.Log.TimeFormat,
	}
	logrus.SetFormatter(formatter)

	// 其他日志配置...

	var level logrus.Level
	var err error
	var logWriter *rotates.RotateLogs

	switch cfg.Log.Level {
	case "DEBUG":
		level = logrus.DebugLevel
	case "WARN":
		level = logrus.WarnLevel
	case "INFO":
		level = logrus.InfoLevel
	case "ERROR":
		level = logrus.ErrorLevel
	case "FATAL":
		level = logrus.FatalLevel
	case "PANIC":
		level = logrus.PanicLevel
	default:
		level = logrus.WarnLevel //默认
	}

	//1、判断文件路径和文件是否存在，不存在则创建
	if _, err := os.Stat(cfg.Log.Dir); os.IsNotExist(err) {
		if err := os.MkdirAll(cfg.Log.Dir, os.FileMode(cfg.Permissions.DirectoryMode)); err != nil {
			return err
		}
	}
	logFileName := path.Join(cfg.Log.Dir, cfg.Log.Filename)

	//2、判断是否设置日志级别，默认为WARN级别
	if level < logrus.PanicLevel || level > logrus.TraceLevel {
		logrus.Errorln("init log failed,level not supported!")
		logrus.SetLevel(logrus.WarnLevel)
	} else {
		logrus.SetLevel(level)
	}

	//3、日志切割功能，按时间来切割
	osVersion := runtime.GOOS
	if osVersion == "windows" {
		logWriter, err = rotates.New(
			logFileName+".%Y%m%d%H%M",
			rotates.WithMaxAge(time.Duration(cfg.Log.MaxAge)*time.Hour),           //文件最大保存时间
			rotates.WithRotationTime(time.Duration(cfg.Log.RotateTime)*time.Hour), //文件切割间隔
		)
	} else if osVersion == "linux" {
		logWriter, err = rotates.New(
			logFileName+".%Y%m%d%H%M",
			rotates.WithLinkName(logFileName),                                     //文件软链接
			rotates.WithMaxAge(time.Duration(cfg.Log.MaxAge)*time.Hour),           //文件最大保存时间
			rotates.WithRotationTime(time.Duration(cfg.Log.RotateTime)*time.Hour), //文件切割间隔
		)
	}

	if err != nil {
		return err
	}

	//创建 local file system hook
	//不同的日志级别写入不同的日志文件
	lfHook := lfshook.NewHook(lfshook.WriterMap{
		logrus.DebugLevel: logWriter,
		logrus.InfoLevel:  logWriter,
		logrus.WarnLevel:  logWriter,
		logrus.ErrorLevel: logWriter,
		logrus.FatalLevel: logWriter,
		logrus.PanicLevel: logWriter,
	}, &logrus.TextFormatter{TimestampFormat: cfg.Log.TimeFormat, FullTimestamp: true})

	logrus.AddHook(lfHook)
	return nil
}

func main() {
	cfg, err := config.LoadConfig("config.yaml")
	if err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// 初始化日志
	if err := InitLogger(cfg); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	// 开始启动隐蔽隧道检测器
	logrus.Info("Starting convert tunnel detector...")

	// 创建context用于控制生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建pipeline
	p := pipeline.NewPipeline()

	// 设置pipeline配置
	if err := p.SetConfig(cfg); err != nil {
		logrus.Fatalf("Failed to set pipeline config: %v", err)
	}

	// 创建数据源
	var src pipeline.Source
	if cfg.Source.Type == "file" {
		fileSource, err := source.NewPcapFileSource(cfg.Source.Filename, cfg.Pipeline.BufferSize)
		if err != nil {
			logrus.Fatalf("Failed to create file source: %v", err)
		}
		src = fileSource
	} else {
		liveSource, err := source.NewPcapLiveSource(cfg)
		if err != nil {
			logrus.Fatalf("Failed to create live source: %v", err)
		}
		src = liveSource
	}

	p.SetSource(src)

	// 添加协议解析处理器
	err = p.AddProcessor(processor.NewProtocolParser(cfg.Pipeline.WorkerCount, cfg))
	if err != nil {
		logrus.Errorf("Add Protocol Parser Processor Failed: %s\n", err)
		return
	}

	// 添加特征提取处理器
	err = p.AddProcessor(processor.NewBasicFeatureExtractor(cfg.Pipeline.WorkerCount, cfg))
	if err != nil {
		logrus.Errorf("Add Basic Feature Extractor Failed: %s\n", err)
		return
	}

	// 添加规则引擎处理器
	ruleEngineProcessor, err := processor.NewRuleEngineProcessor(cfg.RuleEngine.RuleDirectory, cfg.Pipeline.WorkerCount, cfg)
	if err != nil {
		logrus.Errorf("Create Rule Engine Processor Failed: %s\n", err)
		return
	}
	err = p.AddProcessor(ruleEngineProcessor)
	if err != nil {
		logrus.Errorf("Add Rule Engine Processor Failed: %s\n", err)
		return
	}

	// 设置输出
	fileSink, err := sink.NewPcapSink(cfg)
	if err != nil {
		logrus.Fatalf("Failed to create file sink: %v", err)
	}
	p.SetSink(fileSink)

	// 启动pipeline
	if err := p.Start(ctx); err != nil {
		logrus.Fatalf("Failed to start pipeline: %v", err)
	}

	logrus.Info("Pipeline have started successfully")

	// 创建 HTTP API 服务
	apiServer := api.NewServer(cfg)

	// 创建规则服务，并注册到 API 服务器
	ruleService := api.NewRuleService(cfg, ruleEngineProcessor)
	apiServer.RegisterRuleService(ruleService)

	// 在独立的 goroutine 中启动 API 服务器
	go func() {
		logrus.Infof("Starting HTTP API server on %s:%s", cfg.API.Host, cfg.API.Port)
		if err := apiServer.Start(); err != nil {
			logrus.Errorf("HTTP API server error: %v", err)
		}
	}()

	// 处理中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 等待中断信号
	sig := <-sigChan
	logrus.Infof("Received signal %v, shutting down...", sig)

	// 优雅退出
	cancel() // 触发 context 取消

	// 关闭 HTTP API 服务器
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), time.Duration(cfg.Timeouts.ShutdownSeconds)*time.Second)
	defer shutdownCancel()

	if err := apiServer.Stop(shutdownCtx); err != nil {
		logrus.Errorf("Error stopping HTTP API server: %v", err)
	}

	// 修改关闭顺序：先关闭数据源
	logrus.Info("Stopping data source...")
	if err := src.Stop(); err != nil {
		logrus.Errorf("Error stopping source: %v", err)
	}

	// 然后关闭 pipeline
	logrus.Info("Stopping pipeline...")
	if err := p.Stop(); err != nil {
		logrus.Errorf("Error stopping pipeline: %v", err)
	}

	logrus.Info("Shutdown complete")
}
