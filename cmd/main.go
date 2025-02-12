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

	"github.com/haolipeng/convert_tunnel_detector/pkg/pipeline"
	"github.com/haolipeng/convert_tunnel_detector/pkg/processor"
	"github.com/haolipeng/convert_tunnel_detector/pkg/sink"
	"github.com/haolipeng/convert_tunnel_detector/pkg/source"
)

func InitLogger(fileName string, logDir string, logLevel string) error {
	var level logrus.Level
	var err error
	var logWriter *rotates.RotateLogs

	switch logLevel {
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
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return err
		}
	}
	logFileName := path.Join(logDir, fileName)

	//2、判断是否设置日志级别，默认为WARN级别
	if level < logrus.PanicLevel || level > logrus.TraceLevel {
		logrus.Errorln("init log failed,level not supported!")
		logrus.SetLevel(logrus.WarnLevel)
	} else {
		logrus.SetLevel(level)
	}

	//3、日志切割功能，按时间来切割
	var osVersion string
	osVersion = runtime.GOOS
	if osVersion == "windows" {
		logWriter, err = rotates.New(
			logFileName+".%Y%m%d%H%M",
			rotates.WithMaxAge(24*time.Hour),    //文件最大保存时间
			rotates.WithRotationTime(time.Hour), //文件切割间隔
		)
	} else if osVersion == "linux" {
		logWriter, err = rotates.New(
			logFileName+".%Y%m%d%H%M",
			rotates.WithLinkName(logFileName),   //文件软链接
			rotates.WithMaxAge(24*time.Hour),    //文件最大保存时间
			rotates.WithRotationTime(time.Hour), //文件切割间隔
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
	}, &logrus.TextFormatter{})

	logrus.AddHook(lfHook)
	return nil
}

func main() {
	// 初始化日志
	if err := InitLogger("tunnelInsight.log", "./logs", "INFO"); err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}

	logrus.Info("Starting convert tunnel detector...")

	// 创建context用于控制生命周期
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 创建pipeline
	p := pipeline.NewPipeline()

	// 创建数据源
	src, err := source.NewPcapSource("ens34") //TODO:优化：从配置文件中读取网口名称
	if err != nil {
		logrus.Fatalf("Failed to create packet source: %v", err)
	}
	p.SetSource(src)

	// 添加处理器
	p.AddProcessor(processor.NewProtocolParser(4))
	p.AddProcessor(processor.NewBasicFeatureExtractor(4))

	// 设置输出
	sink, err := sink.NewFileSink("output.json")
	if err != nil {
		logrus.Fatalf("Failed to create file sink: %v", err)
	}
	p.SetSink(sink)

	// 启动pipeline
	if err := p.Start(ctx); err != nil {
		logrus.Fatalf("Failed to start pipeline: %v", err)
	}

	logrus.Info("Pipeline started successfully")

	// 等待中断信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan
	logrus.Infof("Received signal %v, shutting down...", sig)

	// 优雅退出
	cancel()
	if err := p.Stop(); err != nil {
		logrus.Errorf("Error stopping pipeline: %v", err)
	}

	logrus.Info("Shutdown complete")
}
