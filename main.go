package main

import (
	"flag"
	"runtime"
	"upgradationScript/common"
	"upgradationScript/logger"

	_ "github.com/Khan/genqlient/generate"
	"github.com/OpsMx/go-app-base/version"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	appName    = "upgrade-job"
	configFile = flag.String("configFile", "/app/config/"+appName+".yaml", "Configuration file location")
)

func main() {

	zapConfig := zap.NewProductionConfig()
	zapConfig.Level.SetLevel(zapcore.ErrorLevel)
	logger.Logger, _ = zapConfig.Build()
	logger.Sl = logger.Logger.Sugar()

	zapConfig.Level.SetLevel(zap.DebugLevel)
	logger.Logger, _ = zapConfig.Build()
	logger.Sl = logger.Logger.Sugar()

	logger.Sl.Infow("starting",
		"appName", appName,
		"version", version.VersionString(),
		"gitBranch", version.GitBranch(),
		"gitHash", version.GitHash(),
		"buildType", version.BuildType(),
		"os", runtime.GOOS,
		"arch", runtime.GOARCH,
		"cores", runtime.NumCPU(),
	)

	common.LoadConfigurationFile(*configFile)

	if err := common.StartUpgrade(); err != nil {
		logger.Sl.Fatal(err.Error())
	}

}
