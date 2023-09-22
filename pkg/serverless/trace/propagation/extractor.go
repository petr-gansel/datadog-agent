package propagation

import (
	"strings"

	"gopkg.in/DataDog/dd-trace-go.v1/ddtrace"
)

// TODO:
// use https://github.com/DataDog/dd-trace-go/blob/main/ddtrace/tracer/propagator.go#L16

type Extractor struct {
	Extract func(interface{}) (ddtrace.SpanContext, error)
}

type Extractor interface {
	Extract() TraceContext
	String() string
}

type Extractors []Extractor

type TraceContext struct {
	TraceID          *uint64
	ParentID         *uint64
	SamplingPriority int
}

var (
	DatadogExtractionType = "datadog"
)

var DefaultExtractors = []Extractor{
	datadogExtractor{},
}

func NewExtractors() ([]Extractor, error) {
	return DefaultExtractors, nil
}

func (e Extractors) String() string {
	return strings.Join(e, ",")
}
