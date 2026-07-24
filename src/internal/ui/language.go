package ui

type LanguageCode string

type LanguageOption struct {
	Code        LanguageCode
	Name        string
	ButtonLabel string
}

const languagePreferenceKey = "ui.language"

var knownLanguageOptions = []LanguageOption{
	{Code: "en", Name: "English"},
	{Code: "ru", Name: "Русский"},
	{Code: "de", Name: "Deutsch"},
	{Code: "fr", Name: "Français"},
	{Code: "it", Name: "Italiano"},
	{Code: "es", Name: "Español"},
	{Code: "zh-Hans", Name: "简体中文", ButtonLabel: "zh"},
	{Code: "hi", Name: "हिन्दी"},
	{Code: "ko", Name: "한국어"},
}

func languageButtonLabel(code LanguageCode) string {
	for _, option := range knownLanguageOptions {
		if option.Code != code {
			continue
		}
		if option.ButtonLabel != "" {
			return option.ButtonLabel
		}
		break
	}
	return string(code)
}

func bundledLanguageOptions() []LanguageOption {
	loaded := localizationState.loadedCodes()
	options := make([]LanguageOption, 0, len(knownLanguageOptions))
	for _, opt := range knownLanguageOptions {
		if loaded[opt.Code] {
			options = append(options, opt)
		}
	}
	return options
}
