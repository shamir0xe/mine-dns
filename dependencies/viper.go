package dependencies

import "github.com/spf13/viper"

func NewViperConfig() (*viper.Viper, error) {
	cfg := viper.New()
	cfg.AddConfigPath(".")
	cfg.SetConfigFile("config.yaml")

	if err := cfg.ReadInConfig(); err != nil {
		return nil, err
	}
	return cfg, nil
}
