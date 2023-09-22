package propagation

type datadogExtractor struct{}

var _ Extractor = datadogExtractor{}

func (e datadogExtractor) Extract() TraceContext {
	return TraceContext{}
}

func (e datadogExtractor) String() string {
	return DatadogExtractionType
}
